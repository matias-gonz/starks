use starks::field::FieldElement;

fn generate_trace(
    f: fn(FieldElement) -> FieldElement,
    a0: FieldElement,
    n: usize,
) -> Vec<FieldElement> {
    let mut trace = Vec::with_capacity(n);
    let mut a = a0;
    for _ in 0..n {
        trace.push(a);
        a = f(a);
    }
    trace
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod test {
    use starks::field::FieldElement;

    use crate::generate_trace;

    #[test]
    fn test_generate_trace() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 20;
        let trace = generate_trace(f, x0, n);
        assert!(trace.len() == n);
        assert!(trace[0] == x0);
        for i in 1..n {
            assert!(trace[i] == f(trace[i - 1]));
        }
    }
}
