use starks::{field::FieldElement, polynomial::{Polynomial, x}};
use sha256::digest;

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

fn generate_generator() -> Vec<FieldElement> {
    let pow = 5;
    let generator_size = 2usize.pow(pow);
    let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
    let G: Vec<FieldElement> = (0..generator_size).into_iter().map(|i| g.pow(i)).collect();
    G
}

fn generate_larger_domain() -> Vec<FieldElement> {
    let w = FieldElement::generator();
    //We will use a blowup of 8. 8*|D0| = 8*20 = 160
    let exp = (2usize.pow(30) * 3) / 160;
    let h = w.pow(exp);
    let H: Vec<FieldElement> = (0..160).into_iter().map(|i| h.pow(i)).collect(); 
    let eval_domain: Vec<FieldElement> = H.into_iter().map(|x| w * x).collect();
    eval_domain
}

fn main() {
    println!("First we generate the trace. a0 is 2 and then we calculate the first 20 elements an+1 = an^8");
    let f = |x: FieldElement| x.pow(8);
    let x0 = FieldElement::new(2);
    let n = 20;
    let trace = generate_trace(f, x0, n);
    println!("Trace is {:?}", trace);

    println!("Now we calculate a suitable generator g modulo 3221225473");
    let pow = 5;
    let generator_size = 2usize.pow(pow);
    let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
    println!("g is {:?}", g);
    let G: Vec<FieldElement> = (0..generator_size).into_iter().map(|i| g.pow(i)).collect();
    let mut b = FieldElement::one();
    for i in 0..(generator_size - 1) {
        println!("b is {:?} and G[i] is {:?}", b, G[i]);
        b = b * g;
    }
    if b * g == FieldElement::one() {
        println!("Success!");
    } else {
        println!("g is of order > 20");
    }

    println!("Let's interpolate the Polynomial");
    let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(1).rev().collect();
    xs.truncate(20);
    let f: Polynomial = Polynomial::interpolate(&xs, &trace);
    for i in 0..(19) {
        println!("X: {:?} -> Trace: {:?}", xs[i], trace[i]);
    }

    println!("Evaluate on a larger domain (8 times larger)");
    let eval_domain: Vec<FieldElement> = generate_larger_domain();
    let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
    let interpolated_f_eval: Vec<FieldElement> = eval_domain.into_iter().map(|d| interpolated_f.clone().eval(d)).collect();
    let hashed = digest(format!("{:?}", interpolated_f_eval));

    println!("Evaluate first constraint that if f(x) - 2 = 0");
    let numer0: Polynomial = f.clone() - FieldElement::new(2);
    let denom0: Polynomial = x() - FieldElement::new(2);
    println!("The reminder of the division is : {:?}", numer0.clone() % denom0.clone());
    let p0: Polynomial = numer0 / denom0;
    println!("The result of the division is a polynomial: {:?}", p0);

}

#[cfg(test)]
mod test {
    use starks::{field::FieldElement, polynomial::{Polynomial, x}};
    use sha256::digest;

    use crate::{generate_trace, generate_generator, generate_larger_domain};

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

    #[test]
    fn test_generator_g() {
        let pow = 5;
        let generator_size = 2usize.pow(pow);
        let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
        let G: Vec<FieldElement> = generate_generator();
        assert!(g.is_order(generator_size), "The generator g is of wrong order.");
        let mut b = FieldElement::one();
        for i in 0..(generator_size - 1) {
            assert_eq!(b, G[i], "The i-th place in G is not equal to the i-th power of g.");
            b = b * g;
            let wrong_order = i + 1;
            assert!(b != FieldElement::one(), "g is of order {wrong_order}");
        }
    }

    #[test]
    fn interpolate_Polynomial() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 20;
        let trace = generate_trace(f, x0, n);

        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(1).rev().collect();
        xs.truncate(20);
        let f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let v = f(2);
        assert_eq!(v, FieldElement::new(1104509596));
    }

    #[test]
    fn extend_larger_domain() {
        let w = FieldElement::generator();
        let eval_domain = generate_larger_domain();
        let field_generator = FieldElement::generator();
        let w_inverse = w.inverse();

        for i in 0..160 {
            assert_eq!((w_inverse * eval_domain[1]).pow(i) * field_generator, eval_domain[i]);
        }
    }

    #[test]
    fn evaluate_on_coset() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 20;
        let trace = generate_trace(f, x0, n);

        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(1).rev().collect();
        xs.truncate(20);

        let eval_domain = generate_larger_domain();

        let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let interpolated_f_eval: Vec<FieldElement> = eval_domain.into_iter().map(|d| interpolated_f.clone().eval(d)).collect();
        let hashed = digest(format!("{:?}", interpolated_f_eval));
        assert_eq!("ad75070407a245cee6d06b0d7446eb77884b802f348e84222fe37fc394cdf02d".to_string(), hashed);
    }

    #[test]
    fn evaluate_first_constraint() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 20;
        let trace = generate_trace(f, x0, n);

        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(1).rev().collect();
        xs.truncate(20);

        let eval_domain = generate_larger_domain();

        let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let interpolated_f_eval: Vec<FieldElement> = eval_domain.into_iter().map(|d| interpolated_f.clone().eval(d)).collect();
        let hashed = digest(format!("{:?}", interpolated_f_eval));

        let numer0: Polynomial = interpolated_f.clone() - FieldElement::new(2);
        let denom0: Polynomial = x() - FieldElement::new(2);
        let p0: Polynomial = numer0 / denom0;
    }
}
