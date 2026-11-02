use crate::domain::errors::DomainError;

/// 可撤销操作的领域值对象
pub struct UndoAction {
    pub description: String,
    action: Box<dyn FnOnce() -> Result<(), DomainError> + Send>,
}

impl UndoAction {
    pub fn new(description: String, action: Box<dyn FnOnce() + Send>) -> Self {
        Self::try_new(
            description,
            Box::new(|| {
                action();
                Ok(())
            }),
        )
    }

    pub fn try_new(
        description: String,
        action: Box<dyn FnOnce() -> Result<(), DomainError> + Send>,
    ) -> Self {
        Self {
            description,
            action,
        }
    }

    /// 执行撤销操作（消费自身，确保只执行一次）
    pub fn execute(self) -> Result<(), DomainError> {
        (self.action)()
    }
}
