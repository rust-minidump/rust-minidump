use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

// This is not how you write an async executor
// But we're fuzzing on in-memory data, so we should *never* actually need to do IO

struct NopWaker;

impl std::task::Wake for NopWaker {
    fn wake(self: Arc<Self>) {}
}

pub fn fuzzing_block_on<O, F: Future<Output = O>>(fut: F) -> O {
    pin_utils::pin_mut!(fut);
    let waker = std::task::Waker::from(Arc::new(NopWaker));
    let mut context = std::task::Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut context) {
            Poll::Ready(v) => return v,
            Poll::Pending => {}
        }
    }
}
