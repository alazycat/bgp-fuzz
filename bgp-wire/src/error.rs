#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Incomplete { min_required: usize, actual: usize },
    UnknownAttribute { code: u8 },
}
