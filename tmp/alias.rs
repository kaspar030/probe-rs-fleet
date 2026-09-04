#[derive(Debug, Clone, PartialEq)]
pub struct NodeId(pub String);
pub type AgentId = NodeId;
fn main() {
    let a = AgentId("x".to_owned());
    let AgentId(inner) = a.clone();
    assert_eq!(inner, "x");
    println!("ok {a:?}");
}
