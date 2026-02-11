#![allow(unsafe_op_in_unsafe_fn)]

use arrow::pyarrow::ToPyArrow;
use arrow::record_batch::RecordBatch;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};

mod builder;
mod parser;
mod schema;
mod transform;

use crate::parser::parse_nessus_arrow;

#[pyclass]
struct NessusParser {
    path: String,
}

#[pymethods]
impl NessusParser {
    #[new]
    fn new(path: String) -> Self {
        NessusParser { path }
    }

    fn parse(&self, py: Python) -> PyResult<PyObject> {
        let batches: Vec<RecordBatch> = parse_nessus_arrow(&self.path).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Nessus Arrow Parse Error: {:#}", e))
        })?;

        if batches.is_empty() {
             return Ok(py.None());
        }

        let pyarrow: Bound<'_, PyModule> = py.import_bound("pyarrow")?;
        let table_class: Bound<'_, PyAny> = pyarrow.getattr("Table")?;

        let py_batches: Result<Vec<PyObject>, _> = batches
            .iter()
            .map(|rb| rb.to_pyarrow(py))
            .collect();
        
        let batch_list: Bound<'_, PyList> = PyList::new_bound(py, py_batches?);
        let args: Bound<'_, PyTuple> = PyTuple::new_bound(py, &[batch_list]);
        let table: Bound<'_, PyAny> = table_class.call_method1("from_batches", args)?;

        Ok(table.into())
    }
}

#[pymodule]
fn fast_nessus_parser(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NessusParser>()?;
    Ok(())
}