/// 可撤销操作的领域值对象
pub struct UndoAction {
    pub description: String,
    action: Box<dyn FnOnce() + Send>,
}

impl UndoAction {
    pub fn new(description: String, action: Box<dyn FnOnce() + Send>) -> Self {
        Self {
            description,
            action,
        }
    }

    /// 执行撤销操作（消费自身，确保只执行一次）
    pub fn execute(self) {
        (self.action)();
    }
}
