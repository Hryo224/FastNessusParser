#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};

mod parser;
mod schema;
mod transform;

use crate::parser::{parse_nessus_native, parse_scan_metadata};
use crate::schema::{NessusFinding, ScanMetadata};

#[pyclass]
struct NessusReport {
    findings: Vec<NessusFinding>,
    metadata: ScanMetadata,
}

#[pymethods]
impl NessusReport {
    fn __len__(&self) -> usize {
        self.findings.len()
    }

    #[getter]
    fn findings(&self, py: Python) -> PyResult<PyObject> {
        self.as_dicts(py)
    }

    #[getter]
    fn metadata(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let json_str: String = serde_json::to_string(&self.metadata).unwrap();
            let json: Bound<'_, PyModule> = py.import_bound("json")?;
            let dict: Bound<'_, PyAny> = json.call_method1("loads", (json_str,))?;
            Ok(dict.into())
        })
    }

    fn as_dicts(&self, py: Python) -> PyResult<PyObject> {
        let json_str: String = serde_json::to_string(&self.findings).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Serialization Error: {}", e))
        })?;

        let json_module: Bound<'_, PyModule> = py.import_bound("json")?;
        let py_list: Bound<'_, PyAny> = json_module.call_method1("loads", (json_str,))?;

        Ok(py_list.into())
    }

fn as_arrow(&self, py: Python) -> PyResult<PyObject> {
        let dicts: Py<PyAny> = self.as_dicts(py)?;
        let pyarrow: Bound<'_, PyModule> = py.import_bound("pyarrow")?;
        let table_class: Bound<'_, PyAny> = pyarrow.getattr("Table")?;
        
        let args: Bound<'_, PyTuple> = PyTuple::new_bound(py, &[dicts]);
        let table: Bound<'_, PyAny> = table_class.call_method1("from_pylist", args)?;

        let drop_cols = PyList::new_bound(py, &["host_properties"]);
        let table: Bound<'_, PyAny> = table.call_method1("drop_columns", (drop_cols,))?;

        Ok(table.into())
    }

    fn as_df(&self, py: Python) -> PyResult<PyObject> {
        let arrow_table: Bound<'_, PyAny> = self.as_arrow(py)?.into_bound(py);
        let df: Bound<'_, PyAny> = arrow_table.call_method0("to_pandas")?;
        Ok(df.into())
    }
}

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

    fn parse(&self) -> PyResult<NessusReport> {
        let findings: Vec<NessusFinding> = parse_nessus_native(&self.path).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Nessus Parse Error: {:#}", e))
        })?;

        let metadata: ScanMetadata = parse_scan_metadata(&self.path).unwrap_or_default();

        Ok(NessusReport { findings, metadata })
    }
}

#[pymodule]
fn fast_nessus_parser(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NessusParser>()?;
    m.add_class::<NessusReport>()?;
    Ok(())
}
