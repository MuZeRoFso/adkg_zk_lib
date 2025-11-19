use bi_polynomial::*;
use zk_tool::*;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use rand::thread_rng;

// ----------------------
// 1. 定义参数与数据结构
// ----------------------
const N: usize = 16; // 总节点数
const T: usize = 5;  // 恢复阈值
const F: usize = 5;  // 恶意节点数 (此处用于后续集合选择)
#[test]
fn test_adkg() {
    

}