pub trait Container: Clone + Eq {
    type Message;

    fn commit(&mut self, msg: &Self::Message);

    fn verify(&self, msg: &Self::Message, origin: &Self) -> bool {
        let mut origin = origin.clone();
        origin.commit(msg);
        origin == *self
    }
}
