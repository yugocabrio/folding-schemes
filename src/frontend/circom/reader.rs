// circom/reader.rs
use anyhow::bail;
use byteorder::{LittleEndian, ReadBytesExt};
use itertools::Itertools;
use std::collections::BTreeMap;
use std::env::current_dir;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use std::process::Command;
use std::str;


use super::circuit::{CircuitJson, R1CS};
use super::file::{from_reader, read_field};


 
use ark_ff::PrimeField;
use nova_snark::traits::Group;

use nova_scotia::FileLocation;

/// load r1cs file by filename with autodetect encoding (bin or json)
pub fn load_r1cs<G1, G2>(filename: &FileLocation) -> R1CS<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let filename = match filename {
        FileLocation::PathBuf(filename) => filename,
        FileLocation::URL(_) => panic!("unreachable"),
    };
    if filename.ends_with("json") {
        load_r1cs_from_json_file(filename)
    } else {
        load_r1cs_from_bin_file::<G1, G2>(filename)
    }
}

#[cfg(target_family = "wasm")]
pub use crate::circom::wasm::load_r1cs;

/// load r1cs from json file by filename
fn load_r1cs_from_json_file<Fr: PrimeField>(filename: &Path) -> R1CS<Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_r1cs_from_json(BufReader::new(reader))
}

/// load r1cs from json by a reader
fn load_r1cs_from_json<Fr: PrimeField, R: Read>(reader: R) -> R1CS<Fr> {
    let circuit_json: CircuitJson = serde_json::from_reader(reader).expect("unable to read.");

    let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
    let num_aux = circuit_json.num_variables - num_inputs;

    let convert_constraint = |lc: &BTreeMap<String, String>| {
        lc.iter()
            .map(|(index, coeff)| (index.parse().unwrap(), Fr::from_str_vartime(coeff).unwrap()))
            .collect_vec()
    };

    let constraints = circuit_json
        .constraints
        .iter()
        .map(|c| {
            (
                convert_constraint(&c[0]),
                convert_constraint(&c[1]),
                convert_constraint(&c[2]),
            )
        })
        .collect_vec();

    R1CS {
        num_inputs,
        num_aux,
        num_variables: circuit_json.num_variables,
        constraints,
    }
}

/// load r1cs from bin file by filename
fn load_r1cs_from_bin_file<G1, G2>(filename: &Path) -> R1CS<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_r1cs_from_bin::<_, G1, G2>(BufReader::new(reader))
}

/// load r1cs from bin by a reader
pub(crate) fn load_r1cs_from_bin<R: Read + Seek, G1, G2>(reader: R) -> R1CS<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let file = from_reader::<_, G1, G2>(reader).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    R1CS {
        num_aux,
        num_inputs,
        num_variables,
        constraints: file.constraints,
    }
}
