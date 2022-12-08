//! Process management syscalls

use core::mem::size_of;
use core::ops::Add;
use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{kernel_copy_to_user, MapPermission, VirtAddr, VPNRange};
use crate::task::{current_user_token, exit_current_and_run_next, suspend_current_and_run_next, any_vpn_mapped_in_current, get_current_task_info, map_in_current, all_vpn_mapped_in_current, TaskStatus, unmap_in_current};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    info!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let us = get_time_us();
    let tm = TimeVal{
        sec: us / 1_000_000,
        usec: us % 1_000_000
    };

    let tm_ptr = unsafe{
        core::mem::transmute::<&TimeVal, *const u8>(&tm)
    };

    let ts_ptr = unsafe{core::mem::transmute::<*mut TimeVal, *mut u8>(ts)};

    kernel_copy_to_user(tm_ptr, current_user_token(), ts_ptr, size_of::<TimeVal>());
    0
}

// CLUE: 从 ch4 开始不再对调度算法进行测试~
pub fn sys_set_priority(_prio: isize) -> isize {
    -1
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    let v_start = VirtAddr::from(start);

    if !v_start.aligned(){
        return -1;
    }

    if (port & !0x7 != 0) || (port &0x7 == 0){
        return -1;
    }

    let mut map_permit = MapPermission::empty();
    map_permit |= MapPermission::U;

    if (port & 0x01) != 0{
        map_permit |= MapPermission::R;
    }

    if (port & 0x02) != 0{
        map_permit |= MapPermission::W;
    }

    if (port & 0x04) != 0{
        map_permit |= MapPermission::X;
    }

    let v_end = VirtAddr::from(start.add(len));
    let vpn_start = v_start.floor();
    let vpn_end = v_end.ceil();
    let map_range = VPNRange::new(vpn_start, vpn_end);

    if any_vpn_mapped_in_current(map_range){
        return -1;
    }

    map_in_current(v_start, v_end, map_permit);
    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    let start_va = VirtAddr::from(start);

    if !start_va.aligned(){
        return -1;
    }

    let start_vpn = start_va.floor();
    let end_va = VirtAddr::from(start + len);
    let end_vpn = end_va.ceil();

    if !all_vpn_mapped_in_current(VPNRange::new(start_vpn, end_vpn)){
        return -1;
    }

    unmap_in_current(VPNRange::new(start_vpn, end_vpn));
    0
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let kernel_task_info = get_current_task_info();
    let mut syscall_times = [0u32; 500];

    for (call_id, call_times) in kernel_task_info.syscall_times{
        syscall_times[call_id] = call_times as u32;
    }

    let task_info = TaskInfo{
        time: kernel_task_info.running_time,
        status: kernel_task_info.status,
        syscall_times
    };

    let task_info_ptr = unsafe{
        core::mem::transmute::<&TaskInfo, *const u8>(&task_info)
    };

    let ti_ptr = unsafe{
        core::mem::transmute::<*mut TaskInfo, *mut u8>(ti)
    };

    kernel_copy_to_user(task_info_ptr, current_user_token(), ti_ptr, size_of::<TaskInfo>());
    0
}
