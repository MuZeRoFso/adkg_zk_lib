use bls12_381_plus::elliptic_curve::Group;
use bls12_381_plus::{G1Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;

pub fn gen_polynomial_random(
    t: usize, // Threshold
    f: usize, // Malicious Node
    n: usize, // Total number of nodes
) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    // Initialize the random number generator.
    let mut rng = OsRng;
    // Initialize the coefficient matrix.
    let mut u_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(f + 1);
    let mut hat_u_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(f + 1);
    // Randomly generate (t+1) * (f+1) coefficients.
    for _ in 0..=f {
        // Initializes and randomly generates coefficients for each row.
        let mut u_row: Vec<Scalar> = Vec::with_capacity(t + 1);
        let mut hat_u_row: Vec<Scalar> = Vec::with_capacity(t + 1);
        for _ in 0..=t {
            u_row.push(Scalar::random(&mut rng));
            hat_u_row.push(Scalar::random(&mut rng));
        }
        u_matrix.push(u_row);
        hat_u_matrix.push(hat_u_row);
    }
    // Returns two coefficient matrices.
    //init_vandermonde(t, n) generates common parameters for subsequent calculations.
    (u_matrix, hat_u_matrix, init_vandermonde(t, n))
}

pub fn gen_polynomial_with_secret(
    t: usize,             // Threshold
    f: usize,             // Malicious Node
    n: usize,             // Total number of nodes
    secret: &Vec<Scalar>, // A list of secrets to hide
) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    // Using secrets to complete the generation of polynomials.
    let mut rng = OsRng;
    let m = secret.len();
    let mut u_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(f + 1);
    let mut hat_u_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(f + 1);
    for j in 0..=f {
        // Using secrets as the first few coefficients, the remaining coefficients are generated randomly.
        let mut u_row: Vec<Scalar> = Vec::with_capacity(t + 1);
        let mut hat_u_row: Vec<Scalar> = Vec::with_capacity(t + 1);
        match j {
            0 => {
                for i in 0..=t {
                    if i < m {
                        u_row.push(secret[i]);
                    } else {
                        u_row.push(Scalar::random(&mut rng));
                    }
                    hat_u_row.push(Scalar::random(&mut rng));
                }
            }
            _ => {
                for _ in 0..=t {
                    u_row.push(Scalar::random(&mut rng));
                    hat_u_row.push(Scalar::random(&mut rng));
                }
            }
        }
        u_matrix.push(u_row);
        hat_u_matrix.push(hat_u_row);
    }
    (u_matrix, hat_u_matrix, init_vandermonde(t, n))
}

pub fn init_vandermonde(t: usize, n: usize) -> Vec<Vec<Scalar>> {
    // Generates the (t+1) * n vandermonde matrix
    let mut vander_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(n + 1);
    vander_matrix.push(vec![Scalar::ONE; t + 1]);
    for i in 1..=n {
        let mut temp_row: Vec<Scalar> = Vec::with_capacity(t + 1);
        // The first element is always 1
        temp_row.push(Scalar::from(1u64));
        for j in 1..=t {
            temp_row.push(temp_row[j - 1] * Scalar::from(i as u64));
        }
        vander_matrix.push(temp_row);
    }
    vander_matrix
}

pub fn bi2alpha(
    matrix: &Vec<Vec<Scalar>>,
    hat_matrix: &Vec<Vec<Scalar>>,
    vander_matrix: &Vec<Vec<Scalar>>,
    n: usize,
) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    let d1 = matrix[0].len();
    let d2 = matrix.len();
    let mut alpha_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(n + 1);
    let mut hat_alpha_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(n + 1);
    // To easily read the coefficients by index, fill in a coefficient 0 where the index is 0.
    alpha_matrix.push(vec![Scalar::ZERO; d1]);
    hat_alpha_matrix.push(vec![Scalar::ZERO; d1]);
    // The vander matrix is used to compute the new polynomial distributed to each node.
    for i in 1..=n {
        let mut alpha: Vec<Scalar> = Vec::with_capacity(d1 + 1);
        let mut hat_alpha: Vec<Scalar> = Vec::with_capacity(d1 + 1);
        let vander: &Vec<Scalar> = &vander_matrix[i];
        for x in 0..d1 {
            let mut coff: Scalar = Scalar::ZERO;
            let mut hat_coff: Scalar = Scalar::ZERO;
            for y in 0..d2 {
                coff += matrix[y][x] * vander[y];
                hat_coff += hat_matrix[y][x] * vander[y];
            }
            alpha.push(coff);
            hat_alpha.push(hat_coff);
        }
        alpha_matrix.push(alpha);
        hat_alpha_matrix.push(hat_alpha);
    }
    (alpha_matrix, hat_alpha_matrix)
}

pub fn interpolate_poly_scalar(accept: &Vec<(Scalar, Scalar)>) -> Vec<Scalar> {
    // The polynomial of Scalar is computed using Lagrange interpolation.
    let f = accept.len();
    let mut accept_x: Vec<Scalar> = Vec::with_capacity(f);
    for i in 0..f {
        accept_x.push(accept[i].0);
    }
    let l_i: Vec<Vec<Scalar>> = poly_l_x(f, &accept_x);
    let mut coff: Vec<Scalar> = vec![Scalar::ZERO; f];
    for i in 0..f {
        for j in 0..f {
            coff[i] += l_i[j][i] * accept[j].1;
        }
    }
    coff
}

pub fn interpolate_poly_g1(accept: &Vec<(Scalar, G1Projective)>) -> Vec<G1Projective> {
    // The polynomial of G1 is computed using Lagrange interpolation.
    let f = accept.len();
    let mut accept_x: Vec<Scalar> = Vec::with_capacity(f);
    for i in 0..f {
        accept_x.push(accept[i].0);
    }
    let l_i = poly_l_x(f, &accept_x);
    let mut coff: Vec<G1Projective> = vec![G1Projective::identity(); f];
    for i in 0..f {
        for j in 0..f {
            coff[i] += l_i[j][i] * accept[j].1;
        }
    }
    coff
}

fn poly_l_x(f: usize, x: &Vec<Scalar>) -> Vec<Vec<Scalar>> {
    // Calculate the intermediate coefficients of the polynomial.
    let mut l_i: Vec<Vec<Scalar>> = Vec::with_capacity(f);
    for i in 0..f {
        let mut temp_coff: Vec<Scalar> = Vec::with_capacity(f);
        let mut denominator: Scalar = Scalar::ONE;
        let mut numerator: Vec<Scalar> = vec![Scalar::ONE];
        for j in 0..f {
            if i != j {
                denominator *= x[i] - x[j];
                numerator = poly_multiply(numerator, -x[j]);
            }
        }
        denominator = denominator.invert().unwrap();
        for j in 0..f {
            temp_coff.push(numerator[j] * denominator);
        }
        l_i.push(temp_coff);
    }
    l_i
}

fn poly_multiply(p1: Vec<Scalar>, p2: Scalar) -> Vec<Scalar> {
    let mut result: Vec<Scalar> = vec![Scalar::ZERO; p1.len() + 1];
    for i in 0..p1.len() {
        result[i + 1] += p1[i] * Scalar::ONE;
        result[i] += p1[i] * p2;
    }
    result
}

pub fn calculate_point(coef: &Vec<Scalar>, vander: &Vec<Scalar>) -> Scalar {
    // Compute a point using a polynomial and a set of vander parameters.
    let mut p = Scalar::ZERO;
    let d = coef.len();
    for i in 0..d {
        p += coef[i] * vander[i];
    }
    p
}
