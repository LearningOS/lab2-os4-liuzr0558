//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the operating system.
//!
//! Be careful when you see [`__switch`]. Control flow around this function
//! might not be what you expect.

mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::loader::{get_app_data, get_num_app};
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use alloc::vec::Vec;
use lazy_static::*;
pub use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus, KernelTaskInfo};

pub use context::TaskContext;
use crate::mm::{MapArea, MapPermission, MapType, VirtAddr, VPNRange};
use crate::timer::get_time_us;

/// The task manager, where all the tasks are managed.
///
/// Functions implemented on `TaskManager` deals with all task state transitions
/// and task context switching. For convenience, you can find wrappers around it
/// in the module level.
///
/// Most of `TaskManager` are hidden behind the field `inner`, to defer
/// borrowing checks to runtime. You can see examples on how to use `inner` in
/// existing functions on `TaskManager`.
pub struct TaskManager {
    /// total number of tasks
    num_app: usize,
    /// use inner value to get mutable access
    inner: UPSafeCell<TaskManagerInner>,
}

/// The task manager inner in 'UPSafeCell'
struct TaskManagerInner {
    /// task list
    tasks: Vec<TaskControlBlock>,
    /// id of current `Running` task
    current_task: usize,
}

lazy_static! {
    /// a `TaskManager` instance through lazy_static!
    pub static ref TASK_MANAGER: TaskManager = {
        info!("init TASK_MANAGER");
        let num_app = get_num_app();
        info!("num_app = {}", num_app);
        let mut tasks: Vec<TaskControlBlock> = Vec::new();
        for i in 0..num_app {
            tasks.push(TaskControlBlock::new(get_app_data(i), i));
        }
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                })
            },
        }
    };
}

impl TaskManager {
    /// Run the first task in task list.
    ///
    /// Generally, the first task in task list is an idle task (we call it zero process later).
    /// But in ch4, we load apps statically, so the first task is a real app.
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next_task = &mut inner.tasks[0];
        next_task.task_status = TaskStatus::Running;
        next_task.first_run_time = Some(get_time_us());
        let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(&mut _unused as *mut _, next_task_cx_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    /// Change the status of current `Running` task into `Ready`.
    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Ready;
    }

    /// Change the status of current `Running` task into `Exited`.
    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Exited;
    }

    /// Find next task to run and return task id.
    ///
    /// In this case, we only return the first `Ready` task in task list.
    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    /// Get the current 'Running' task's token.
    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_user_token()
    }

    #[allow(clippy::mut_from_ref)]
    /// Get the current 'Running' task's trap contexts.
    fn get_current_trap_cx(&self) -> &mut TrapContext {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_trap_cx()
    }

    /// Switch current `Running` task to the task we have found,
    /// or there is no `Ready` task and we can exit with all applications completed
    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            let next_task = &mut inner.tasks[next];

            if next_task.first_run_time.is_none(){
                next_task.first_run_time = Some(get_time_us());
            }

            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }

    fn increase_task_syscall_count(&self, syscall_id: usize){
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;

        for (call_id, call_times) in &mut inner.tasks[current].syscall_times{
            if *call_id == syscall_id{
                *call_times += 1;
                break;
            }else{
                if *call_id == 0 && *call_times == 0{
                    *call_id = syscall_id;
                    *call_times += 1;
                    break;
                }
            }
        }
    }

    fn get_task_task_info(&self) -> KernelTaskInfo{
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let current_time = get_time_us();
        let start_time = inner.tasks[current].first_run_time
            .expect("Why task is running but start time is None!");

        KernelTaskInfo{
            status: inner.tasks[current].task_status,
            syscall_times: inner.tasks[current].syscall_times,
            running_time: (current_time - start_time) / 1000,
        }
    }

    fn any_vpn_mapped(&self, vpn_range: VPNRange) -> bool{
        let inner = self.inner.exclusive_access();
        let current_task = &inner.tasks[inner.current_task];
        current_task.memory_set.any_vpn_mapped(vpn_range)
    }

    fn all_vpn_mapped(&self, vpn_range: VPNRange) -> bool{
        let inner = self.inner.exclusive_access();
        let current_task = &inner.tasks[inner.current_task];
        current_task.memory_set.all_vpn_mapped(vpn_range)
    }

    fn map_in_current(&self, va_start: VirtAddr, va_end: VirtAddr, permit: MapPermission){
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let current_task = &mut inner.tasks[current];
        current_task.memory_set.push(MapArea::new(va_start, va_end, MapType::Framed, permit), None);
    }

    fn unmap_in_current(&self, vpn_range: VPNRange){
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        let current_task = &mut inner.tasks[current];
        current_task.memory_set.pop(vpn_range);
    }
}

/// Run the first task in task list.
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// Switch current `Running` task to the task we have found,
/// or there is no `Ready` task and we can exit with all applications completed
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// Change the status of current `Running` task into `Ready`.
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// Change the status of current `Running` task into `Exited`.
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// Suspend the current 'Running' task and run the next task in task list.
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

/// Get the current 'Running' task's token.
pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

/// Get the current 'Running' task's trap contexts.
pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

pub fn increase_task_syscall_count(syscall_id: usize){
    TASK_MANAGER.increase_task_syscall_count(syscall_id);
}

pub fn get_current_task_info() -> KernelTaskInfo{
    TASK_MANAGER.get_task_task_info()
}

pub fn any_vpn_mapped_in_current(vpn_range: VPNRange) -> bool{
    TASK_MANAGER.any_vpn_mapped(vpn_range)
}

pub fn all_vpn_mapped_in_current(vpn_range: VPNRange) -> bool{
    TASK_MANAGER.all_vpn_mapped(vpn_range)
}

pub fn map_in_current(va_start: VirtAddr, va_end: VirtAddr, permit: MapPermission){
    TASK_MANAGER.map_in_current(va_start, va_end, permit);
}

pub fn unmap_in_current(vpn_range: VPNRange){
    TASK_MANAGER.unmap_in_current(vpn_range);
}

