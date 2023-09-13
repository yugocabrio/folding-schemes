use std::{collections::HashMap, path::{Path, PathBuf}};

use nova_scotia::{
    circom::reader::generate_witness_from_bin,  FileLocation, F, S,
};

use nova_snark::{
    provider,
    traits::Group,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use num_bigint::BigInt;
use num_traits::Num;

use ark_ff;
use crate::ccs::r1cs::R1CS;
use crate::utils::vec::SparseMatrix;

mod reader;
mod file;
mod circuit;

#[cfg(not(target_family = "wasm"))]
use nova_scotia::circom::reader::generate_witness_from_wasm;

#[cfg(target_family = "wasm")]
use nova_scotia::circom::wasm::generate_witness_from_wasm;

fn extract_r1cs<F: ark_ff::PrimeField>(
    r1cs: &circuit::R1CS<F>
) -> R1CS<F> 
{
    // NovaR1CSの行をSparseMatrixの形式に変換するヘルパー関数
    fn convert_matrix_row<F>(row: &[(usize, F)]) -> Vec<(F, usize)> {
        row.iter().map(|(idx, coeff)| {
            (*coeff, *idx)
        }).collect()
    }

    let n_rows = r1cs.constraints.len();

    // nova_scotia R1CSからマトリックスを抽出
    let a_matrix: Vec<_> = r1cs.constraints.iter().map(|(a, _, _)| convert_matrix_row(a)).collect();
    let b_matrix: Vec<_> = r1cs.constraints.iter().map(|(_, b, _)| convert_matrix_row(b)).collect();
    let c_matrix: Vec<_> = r1cs.constraints.iter().map(|(_, _, c)| convert_matrix_row(c)).collect();

    R1CS {
        l: r1cs.num_inputs as usize + r1cs.num_aux as usize, // Assuming 'l' is sum of inputs and auxiliaries
        A: SparseMatrix {
            n_rows,
            n_cols: r1cs.num_variables,
            coeffs: a_matrix,
        },
        B: SparseMatrix {
            n_rows,
            n_cols: r1cs.num_variables,
            coeffs: b_matrix,
        },
        C: SparseMatrix {
            n_rows,
            n_cols: r1cs.num_variables,
            coeffs: c_matrix,
        },
    }
}

/*
#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn compute_witness_vector<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
) -> Vec<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = match &witness_generator_file {
        FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
        FileLocation::URL(_) => true,
    };
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F<G1>>(
            &witness_generator_file,
            &input_json,
            &Path::new("path_to_witness_output"),
        )
    } else {
        let witness_generator_file = match &witness_generator_file {
            FileLocation::PathBuf(path) => path,
            FileLocation::URL(_) => panic!("unreachable"),
        };
        generate_witness_from_bin::<F<G1>>(
            &witness_generator_file,
            &input_json,
            &Path::new("path_to_witness_output"),
        )
    }
}
*/
pub fn circom_parser() {
    let group_name = "bn254";
    let circuit_filepath = format!("src/{}/with_minus.r1cs", group_name);

    let root = std::env::current_dir().unwrap();

    type G1 = provider::bn256_grumpkin::bn256::Point;
    type G2 = provider::bn256_grumpkin::grumpkin::Point;

    let circuit_file = root.join(circuit_filepath);

    let r1cs = reader::load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));


    let r1cs_converted = extract_r1cs::<F>(&r1cs);



    /*
    let current_public_input = [F::<G1>::from(2)];

    let current_public_input_hex = current_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let current_public_inputs = current_public_input_hex.clone();

    // let mut private_inputs = Vec::new();
    let mut private_input = HashMap::new();
    // private_input.insert("adder".to_string(), json!(3));
    // private_inputs.push(private_input);
    let witness_gen_filepath = format!("src/{}/toy_js/with_minus.wasm", group_name);
    let witness_generator_file = FileLocation::PathBuf(root.join(witness_gen_filepath));

    let witness_vector = compute_witness_vector::<G1, G2>(current_public_inputs, private_input, witness_generator_file);
    println!("\nWitness Vector: \n{:?}", witness_vector);
    */
}