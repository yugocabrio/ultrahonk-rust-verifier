fn fib10(a0: Field, a1: Field) -> Field {
    let mut prev = a0;
    let mut curr = a1;
    for _ in 0..10 {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }
    curr
}

pub fn main(a0: Field, a1: Field, out: pub Field) {
    let result = fib10(a0, a1);
    assert(result == out);
}
