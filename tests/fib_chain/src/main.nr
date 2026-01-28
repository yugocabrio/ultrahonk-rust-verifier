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

#[test]
fn test_fib10() {
    // 0,1 -> after 10 iterations, curr = 89
    let a0 = 0;
    let a1 = 1;
    let out = 89;
    main(a0, a1, out);
}

