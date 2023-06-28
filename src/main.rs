use sha256::digest;
use starks::{
    channel::Channel,
    field::FieldElement,
    merkle_tree::MerkleTree,
    polynomial::{x, Polynomial},
};

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

fn generate_trace_3(a0: FieldElement, n: usize) -> Vec<FieldElement> {
    let mut trace = Vec::with_capacity(n);
    trace.push(a0);
    for i in 1..n {
        let a = *trace.last().unwrap();
        if i % 2 == 0 {
            trace.push(a.pow(4));
        } else {
            trace.push(a.pow(2));
        }
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

fn get_CP(p0: Polynomial, p1: Polynomial, channel: &mut Channel) -> Polynomial {
    let alpha0 = channel.receive_random_field_element();
    let alpha1 = channel.receive_random_field_element();
    (p0 * alpha0) + (p1 * alpha1)
}

fn cp_eval(
    p0: Polynomial,
    p1: Polynomial,
    domain: Vec<FieldElement>,
    channel: &mut Channel,
) -> (Polynomial, Vec<FieldElement>) {
    let cp = get_CP(p0, p1, channel);
    let cp_evaluation = domain.into_iter().map(|d| cp(d)).collect();
    (cp, cp_evaluation)
}

fn next_fri_domain(fri_domain: Vec<FieldElement>) -> Vec<FieldElement> {
    let fri_domain_len = fri_domain.len();
    fri_domain
        .into_iter()
        .take(fri_domain_len / 2)
        .map(|x| x.pow(2))
        .collect()
}

fn next_fri_polynomial(poly: Polynomial, beta: FieldElement) -> Polynomial {
    let odd_coefficients: Vec<FieldElement> =
        poly.0.clone().into_iter().skip(1).step_by(2).collect();
    let even_coefficients: Vec<FieldElement> = poly.0.into_iter().step_by(2).collect();
    let odd = Polynomial::new(&odd_coefficients) * beta;
    let even = Polynomial::new(&even_coefficients);
    odd + even
}

fn next_fri_layer(
    poly: Polynomial,
    domain: Vec<FieldElement>,
    beta: FieldElement,
) -> (Polynomial, Vec<FieldElement>, Vec<FieldElement>) {
    let next_poly = next_fri_polynomial(poly, beta);
    let next_domain = next_fri_domain(domain);
    let next_layer: Vec<FieldElement> = next_domain
        .clone()
        .into_iter()
        .map(|x| next_poly(x))
        .collect();
    (next_poly, next_domain, next_layer)
}

fn fri_commit(
    cp: Polynomial,
    domain: Vec<FieldElement>,
    cp_eval: Vec<FieldElement>,
    cp_merkle: MerkleTree,
    channel: &mut Channel,
) -> (Vec<Vec<FieldElement>>, Vec<MerkleTree>) {
    let mut fri_polys: Vec<Polynomial> = vec![cp];
    let mut fri_domains: Vec<Vec<FieldElement>> = vec![domain];
    let mut fri_layers: Vec<Vec<FieldElement>> = vec![cp_eval];
    let mut fri_merkles: Vec<MerkleTree> = vec![cp_merkle];
    while fri_polys.last().unwrap().degree() > 1 {
        let beta = channel.receive_random_field_element();
        let last_poly = fri_polys.last().unwrap().clone();
        let last_domain = fri_domains.last().unwrap().clone();
        let (next_poly, next_domain, next_layer) = next_fri_layer(last_poly, last_domain, beta);
        fri_polys.push(next_poly.clone());
        fri_domains.push(next_domain.clone());
        fri_layers.push(next_layer.clone());
        fri_merkles.push(MerkleTree::new(next_layer));
        channel.send(fri_merkles.last().unwrap().root())
    }
    channel.send(fri_polys.last().unwrap().0[0].0.to_string());

    (fri_layers, fri_merkles)
}

fn decommit_on_fri_layers(
    idx: usize,
    channel: &mut Channel,
    fri_layers: Vec<Vec<FieldElement>>,
    fri_merkles: Vec<MerkleTree>,
) {
    let mut fri_layers = fri_layers;
    let mut fri_merkles = fri_merkles;
    fri_layers.pop().unwrap();
    fri_merkles.pop().unwrap();

    for (layer, merkle) in fri_layers.iter().zip(fri_merkles) {
        let length = layer.len();
        let idx = idx % length;
        let sib_idx = (idx + length / 2) % length;
        //channel.send(layer[idx].to_string());
        channel.send(merkle.get_authentication_path(idx));
        //channel.send(layer[sib_idx].to_string());
        channel.send(merkle.get_authentication_path(sib_idx));
    }
    let last_fri_layer = fri_layers.last().unwrap();
    //channel.send(last_fri_layer[0].to_string());
}

fn decommit_on_query(
    idx: usize,
    channel: &mut Channel,
    f_eval: Vec<FieldElement>,
    f_merkle: MerkleTree,
    fri_layers: Vec<Vec<FieldElement>>,
    fri_merkles: Vec<MerkleTree>,
) {
    let f_eval_len = f_eval.len();
    assert!(
        idx + 16 < f_eval_len,
        "query index: {idx} is out of range. Length of layer: {f_eval_len}."
    );
    channel.send(f_eval[idx].to_string()); // f(x).
    channel.send(f_merkle.get_authentication_path(idx)); // auth path for f(x).
    channel.send(f_eval[idx + 8].to_string()); // f(gx).
    channel.send(f_merkle.get_authentication_path(idx + 8)); // auth path for f(gx).
    channel.send(f_eval[idx + 16].to_string()); // f(g^2x).
    channel.send(f_merkle.get_authentication_path(idx + 16)); // auth path for f(g^2x).
    decommit_on_fri_layers(idx, channel, fri_layers, fri_merkles);
}

fn case_1() {
    let mut channel = Channel::new();
    // First generate the trace. a0 is 2 and calculate the first 21 elements with an+1 = an^8
    let f = |x: FieldElement| x.pow(8);
    let x0 = FieldElement::new(2);
    let n = 21;
    let trace = generate_trace(f, x0, n);

    // Generator should have order 32 = 2^5
    let pow = 5;
    let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
    let G: Vec<FieldElement> = (0..n).map(|i| g.pow(i)).collect();

    // Generate a larger domain: blowup of 8 = 2^3 => Generator should have order 256 = 2^(5 + 3)
    let blowup = 3;
    let w = FieldElement::generator();
    let h = w.pow(3 * 2usize.pow(30 - (pow + blowup)));
    let H: Vec<FieldElement> = (0..n * 2_usize.pow(blowup)).map(|i| h.pow(i)).collect();
    let eval_domain: Vec<FieldElement> = H.into_iter().map(|x| w * x).collect();

    // Interpolate the trace on the first 21 elements of G
    let interpolated_f: Polynomial = Polynomial::interpolate(&G, &trace);
    let interpolated_f_eval: Vec<FieldElement> = eval_domain
        .clone()
        .into_iter()
        .map(|d| interpolated_f.clone().eval(d))
        .collect();

    // Commit interpolation
    let f_merkle = MerkleTree::new(interpolated_f_eval);
    channel.send(f_merkle.root());

    // First constraint: f(x) = 2
    let numer0 = interpolated_f.clone() - FieldElement::new(2);
    let denom0 = x() - FieldElement::one();
    let p0 = numer0 / denom0;

    //  Second constraint: (f(g.x) - (f(x))^8)) / (x - g ^ 0) ... (x - g ^ 19)
    let minus_one = FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
    let numer1: Polynomial = interpolated_f(x() * g);
    let numer2: Polynomial = interpolated_f.pow(8) * minus_one;
    let numer = numer1 + numer2;
    let denom1 = x().pow(32usize) - 1;
    let denom2: Vec<Polynomial> = (20..32).map(|i| x() - g.pow(i)).collect();
    let denom2 = Polynomial::prod(&denom2);
    let denom = denom1 / denom2;
    let p1: Polynomial = numer / denom;

    // Commit on the Composition Polynomial
    let (cp, cp_evaluation) = cp_eval(p0, p1, eval_domain.clone(), &mut channel);
    let cp_merkle: MerkleTree = MerkleTree::new(cp_evaluation.clone());
    channel.send(cp_merkle.root());

    // Commit FRI
    let (fri_layers, fri_merkles) = fri_commit(
        cp,
        eval_domain,
        cp_evaluation.clone(),
        cp_merkle.clone(),
        &mut channel,
    );

    let cp_eval_len = cp_evaluation.len();
    for _ in 0..32 {
        decommit_on_query(
            channel.receive_random_int(0, cp_eval_len - 17, true),
            &mut channel,
            cp_evaluation.clone(),
            cp_merkle.clone(),
            fri_layers.clone(),
            fri_merkles.clone(),
        );
    }
    println!("{:?}", channel.proof);
}

fn case_2() {
    println!("First we generate the trace. a0 is 2 and then we calculate the first 61 elements an+1 = an^2");
    let f = |x: FieldElement| x.pow(2);
    let x0 = FieldElement::new(2);
    let n = 61;
    let trace = generate_trace(f, x0, n);
    println!("Trace is {:?}", trace);

    println!("Now we calculate a suitable generator g modulo 3221225473");
    let pow = 6;
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
        println!("g is of order > 61");
    }

    println!("Let's interpolate the Polynomial");
    let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(3).rev().collect();
    let f: Polynomial = Polynomial::interpolate(&xs, &trace);
    for i in 0..(61) {
        println!("X: {:?} -> Trace: {:?}", xs[i], trace[i]);
    }

    println!("Evaluate on a larger domain (8 times larger)");
    let eval_domain: Vec<FieldElement> = generate_larger_domain();
    let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
    let interpolated_f_eval: Vec<FieldElement> = eval_domain
        .clone()
        .into_iter()
        .map(|d| interpolated_f.clone().eval(d))
        .collect();
    let hashed = digest(format!("{:?}", interpolated_f_eval));

    println!("Evaluate first constraint that if f(x) - 2 = 0");
    let numer0: Polynomial = f.clone() - FieldElement::new(2);
    let denom0: Polynomial = x() - FieldElement::one();
    let p0: Polynomial = numer0.clone() / denom0.clone();
    println!("The result of the division is a polynomial: {:?}", p0);
    println!("Degree of num p0: {:?}", Polynomial::degree(&numer0));
    println!("Degree of den p0: {:?}", Polynomial::degree(&denom0));
    println!("Degree of p0: {:?}", Polynomial::degree(&p0));

    println!("Evaluate second constraint: (f(g.x) - (f(x))^2)) / (x - g ^ 0) ... (x - g ^ 39)");
    let numer1: Polynomial = f(x() * g);
    let numer2: Polynomial =
        f.pow(2) * FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
    let numer = numer1 + numer2;
    let denom1 = (x().pow(64usize) - 1);
    let denom2: Vec<Polynomial> = (60..64).into_iter().map(|i| x() - g.pow(i)).collect();
    let denom2 = Polynomial::prod(&denom2);
    let denom = (denom1 / denom2);
    let p1: Polynomial = numer.clone() / denom.clone();
    println!("Degree of num p1: {:?}", Polynomial::degree(&numer));
    println!("Degree of den p1: {:?}", Polynomial::degree(&denom));
    println!("Degree of p1: {:?}", Polynomial::degree(&p1));

    println!("Composition Polynomial");
    let mut test_channel: Channel = Channel::new();
    let cp0: Polynomial = get_CP(p0.clone(), p1.clone(), &mut test_channel);
    let cp_test_degree = cp0.degree();
    assert_eq!(
        cp0.degree(),
        60,
        "The degree of cp is {cp_test_degree} when it should be 140."
    );

    println!("Commit on the Composition Polynomial");

    let mut channel = Channel::new();
    let (cp, cp_evaluation) = cp_eval(p0.clone(), p1.clone(), eval_domain.clone(), &mut channel);
    let cp_merkle: MerkleTree = MerkleTree::new(cp_evaluation.clone());
    channel.send(cp_merkle.root());

    let next_domain = next_fri_domain(eval_domain.clone());
    let (fri_layers, fri_merkles) = fri_commit(
        cp,
        eval_domain.clone(),
        cp_evaluation.clone(),
        cp_merkle.clone(),
        &mut channel,
    );

    let cp_eval_len = cp_evaluation.len();
    for _ in (0..32) {
        decommit_on_query(
            channel.receive_random_int(0, cp_eval_len - 17, true),
            &mut channel,
            cp_evaluation.clone(),
            cp_merkle.clone(),
            fri_layers.clone(),
            fri_merkles.clone(),
        );
    }
    println!("{:?}", channel.proof);
}

fn case_3() {
    println!("First we generate the trace. a0 is 2 and then we calculate the first 61 elements an+1 = an^2");
    let x0 = FieldElement::new(2);
    let n = 41;
    let trace = generate_trace_3(x0, n);
    println!("Trace is {:?}", trace);

    println!("Now we calculate a suitable generator g modulo 3221225473");
    let pow = 6;
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
        println!("g is of order > 61");
    }

    println!("Let's interpolate the Polynomial");
    let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(23).rev().collect();
    let f: Polynomial = Polynomial::interpolate(&xs, &trace);
    for i in 0..(41) {
        println!("X: {:?} -> Trace: {:?}", xs[i], trace[i]);
    }

    println!("Evaluate on a larger domain (8 times larger)");
    let eval_domain: Vec<FieldElement> = generate_larger_domain();
    let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
    let interpolated_f_eval: Vec<FieldElement> = eval_domain
        .clone()
        .into_iter()
        .map(|d| interpolated_f.clone().eval(d))
        .collect();
    let hashed = digest(format!("{:?}", interpolated_f_eval));

    println!("Evaluate first constraint that if f(x) - 2 = 0");
    let numer0: Polynomial = f.clone() - FieldElement::new(2);
    let denom0: Polynomial = x() - FieldElement::one();
    let p0: Polynomial = numer0.clone() / denom0.clone();
    println!("The result of the division is a polynomial: {:?}", p0);
    println!("Degree of num p0: {:?}", Polynomial::degree(&numer0));
    println!("Degree of den p0: {:?}", Polynomial::degree(&denom0));
    println!("Degree of p0: {:?}", Polynomial::degree(&p0));

    println!("Evaluate second constraint (for odd numbers)");
    let numer1_c1: Polynomial = f(x() * g);
    let numer2_c1: Polynomial =
        f.pow(2) * FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
    let numer_c1 = numer1_c1 + numer2_c1;
    let denom1_c1 = (x().pow(32usize) - 1);
    let denom2_c1: Vec<Polynomial> = (40..64).into_iter().filter(|&num| num % 2 == 0).map(|i| x() - g.pow(i)).collect();
    let denom2_c1 = Polynomial::prod(&denom2_c1);
    let denom_c1 = (denom1_c1 / denom2_c1);
    let p1: Polynomial = numer_c1.clone() / denom_c1.clone();
    println!("Degree of num p1: {:?}", Polynomial::degree(&numer_c1));
    println!("Degree of den p1: {:?}", Polynomial::degree(&denom_c1));
    println!("Degree of p1: {:?}", Polynomial::degree(&p1));

    println!("Evaluate second constraint (for even numbers)");
    let numer1_c2: Polynomial = f(x() * g);
    let numer2_c2: Polynomial =
        f.pow(4) * FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
    let numer_c2 = numer1_c2 + numer2_c2;
    let denom1_c2 = (x().pow(32usize) - 1);
    let denom2_c2: Vec<Polynomial> = (40..64).into_iter().filter(|&num| num % 2 != 0).map(|i| x() - g.pow(i)).collect();
    let denom2_c2 = Polynomial::prod(&denom2_c2);
    let denom_c2 = (denom1_c2 / denom2_c2);
    let p2: Polynomial = numer_c2.clone() / denom_c2.clone();
    println!("Degree of num p1: {:?}", Polynomial::degree(&numer_c2));
    println!("Degree of den p1: {:?}", Polynomial::degree(&denom_c2));
    println!("Degree of p1: {:?}", Polynomial::degree(&p2));
    
}

fn main() {
    println!("CASE 1");
    case_1();
    println!("CASE 2");
    //case_2();
    println!("CASE 3");
    //case_3();
}

#[cfg(test)]
mod test {
    use sha256::digest;
    use starks::{
        channel::Channel,
        field::FieldElement,
        merkle_tree::MerkleTree,
        polynomial::{x, Polynomial},
    };

    use crate::{cp_eval, generate_generator, generate_larger_domain, generate_trace, get_CP};

    #[test]
    fn test_generate_trace() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 21;
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
        assert!(
            g.is_order(generator_size),
            "The generator g is of wrong order."
        );
        let mut b = FieldElement::one();
        for i in 0..(generator_size - 1) {
            assert_eq!(
                b, G[i],
                "The i-th place in G is not equal to the i-th power of g."
            );
            b = b * g;
            let wrong_order = i + 1;
            assert!(b != FieldElement::one(), "g is of order {wrong_order}");
        }
    }

    #[test]
    fn interpolate_Polynomial() {
        let f = |x: FieldElement| x.pow(8);
        let x0: FieldElement = FieldElement::new(2);
        let n = 21;
        let trace = generate_trace(f, x0, n);

        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(11).rev().collect();
        let f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let v = f(2);
        assert_eq!(v, FieldElement::new(2604377568));
    }

    #[test]
    fn extend_larger_domain() {
        let w = FieldElement::generator();
        let eval_domain = generate_larger_domain();
        let field_generator = FieldElement::generator();
        let w_inverse = w.inverse();

        for i in 0..160 {
            assert_eq!(
                (w_inverse * eval_domain[1]).pow(i) * field_generator,
                eval_domain[i]
            );
        }
    }

    #[test]
    fn evaluate_on_coset() {
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 21;
        let trace = generate_trace(f, x0, n);

        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(11).rev().collect();

        let eval_domain = generate_larger_domain();

        let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let interpolated_f_eval: Vec<FieldElement> = eval_domain
            .into_iter()
            .map(|d| interpolated_f.clone().eval(d))
            .collect();
        let hashed = digest(format!("{:?}", interpolated_f_eval));
        assert_eq!(
            "d53fbc8273b1e58ef0f8d00a6c4d8eac5c2b0ec2ea767a114e7403957e77914e".to_string(),
            hashed
        );
    }

    #[test]
    fn evaluate_constraints() {
        let pow = 5;
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 21;
        let trace = generate_trace(f, x0, n);
        let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(11).rev().collect();

        let eval_domain = generate_larger_domain();

        let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let interpolated_f_eval: Vec<FieldElement> = eval_domain
            .into_iter()
            .map(|d| interpolated_f.clone().eval(d))
            .collect();
        let hashed = digest(format!("{:?}", interpolated_f_eval));

        let numer0: Polynomial = interpolated_f.clone() - FieldElement::new(2);
        let denom0: Polynomial = x() - FieldElement::one();
        let nullPolCoef: Vec<FieldElement> = [].to_vec();
        assert_eq!(
            numer0.clone() % denom0.clone(),
            Polynomial::new(&nullPolCoef)
        );
        let p0: Polynomial = numer0 / denom0;

        let numer1: Polynomial = interpolated_f(x() * g);
        let numer2: Polynomial = interpolated_f.pow(8)
            * FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
        let numer = numer1 + numer2;
        let denom1 = (x().pow(32usize) - 1);
        let denom2: Vec<Polynomial> = (19..32).into_iter().map(|i| x() - g.pow(i)).collect();
        let denom2 = Polynomial::prod(&denom2);
        let denom = (denom1 / denom2);
        assert_eq!(numer.clone() % denom.clone(), Polynomial::new(&nullPolCoef));
        let p1: Polynomial = numer / denom;
    }

    #[test]
    fn evaluate_composition_polynomial() {
        let pow = 5;
        let f = |x: FieldElement| x.pow(8);
        let x0 = FieldElement::new(2);
        let n = 21;
        let trace = generate_trace(f, x0, n);
        let g = FieldElement::generator().pow(3 * 2usize.pow(30 - pow));
        let G: Vec<FieldElement> = generate_generator();

        let mut xs: Vec<FieldElement> = G.into_iter().rev().skip(11).rev().collect();

        let eval_domain = generate_larger_domain();

        let interpolated_f: Polynomial = Polynomial::interpolate(&xs, &trace);
        let interpolated_f_eval: Vec<FieldElement> = eval_domain
            .clone()
            .into_iter()
            .map(|d| interpolated_f.clone().eval(d))
            .collect();
        let hashed = digest(format!("{:?}", interpolated_f_eval));

        let numer0: Polynomial = interpolated_f.clone() - FieldElement::new(2);
        let denom0: Polynomial = x() - FieldElement::one();
        let nullPolCoef: Vec<FieldElement> = [].to_vec();
        assert_eq!(
            numer0.clone() % denom0.clone(),
            Polynomial::new(&nullPolCoef)
        );
        let p0: Polynomial = numer0 / denom0;

        let numer1: Polynomial = interpolated_f(x() * g);
        let numer2: Polynomial = interpolated_f.pow(8)
            * FieldElement::new((-1 + FieldElement::k_modulus() as i128) as usize);
        let numer = numer1 + numer2;
        let denom1 = (x().pow(32usize) - 1);
        let denom2: Vec<Polynomial> = (20..32).into_iter().map(|i| x() - g.pow(i)).collect();
        let denom2 = Polynomial::prod(&denom2);
        let denom = (denom1 / denom2);
        assert_eq!(numer.clone() % denom.clone(), Polynomial::new(&nullPolCoef));
        let p1: Polynomial = numer / denom;

        let mut test_channel: Channel = Channel::new();
        let cp_test = get_CP(p0.clone(), p1.clone(), &mut test_channel);
        let cp_test_degree = cp_test.degree();
        assert_eq!(
            cp_test.degree(),
            140,
            "The degree of cp is {cp_test_degree} when it should be 140."
        );

        let mut channel = Channel::new();
        let (cp, cp_evaluation) =
            cp_eval(p0.clone(), p1.clone(), eval_domain.clone(), &mut channel);
        let cp_merkle: MerkleTree = MerkleTree::new(cp_evaluation.clone());
        channel.send(cp_merkle.root());
        assert_eq!(
            cp_merkle.root(),
            "1a597404307c5e3032e6932e8f7d6be23c546374ff2b914fdff5a38915e0ccef",
            "Merkle tree root is wrong."
        );
    }

    #[test]
    fn test_case_two_trace_length() {
        let f1 = |x: FieldElement| x.pow(8);
        let f2 = |x: FieldElement| x.pow(2);
        let x0 = FieldElement::new(2);
        let n1 = 21;
        let trace_1 = generate_trace(f1, x0, n1);

        let n2 = 61;
        let trace_2 = generate_trace(f2, x0, n2);

        assert_eq!(trace_1.last(), trace_2.last());
    }
}
