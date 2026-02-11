use anyhow::{Context, Result};
use arrow::record_batch::RecordBatch;
use memmap2::MmapOptions;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rayon::prelude::*;
use std::fs::File;

use crate::builder::NessusArrowBuilder;
use crate::schema::{HostContext, ReportHost};
use crate::transform::{DerivedContext, HostDerived};

const CHUNK_SIZE: usize = 2000;

pub fn parse_nessus_arrow(path: &str) -> Result<Vec<RecordBatch>> {
    let file: File = File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mmap: memmap2::Mmap = unsafe { MmapOptions::new().map(&file)? };

    let host_ranges: Vec<(usize, usize)> = find_host_ranges(&mmap).context("Failed to index Nessus XML")?;

    let batches: Vec<RecordBatch> = host_ranges
        .par_chunks(CHUNK_SIZE)
        .map(|chunk_ranges| -> Result<RecordBatch> {
            let mut builder = NessusArrowBuilder::new(chunk_ranges.len() * 20);

            for &(start, end) in chunk_ranges {
                let slice: &[u8] = &mmap[start..end];
                
                let host: ReportHost = quick_xml::de::from_reader(slice)?;
                let h_ctx: HostContext = HostContext::from_report_host(&host);
                
                let h_derived: HostDerived = HostDerived::analyze(&h_ctx);

                for item in &host.items {
                    let d_derived: DerivedContext = DerivedContext::calculate(&h_ctx, &h_derived, item);
                    
                    builder.append(&h_ctx, &h_derived, item, &d_derived);
                }
            }
            builder.finish()
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(batches)
}

fn find_host_ranges(data: &[u8]) -> Result<Vec<(usize, usize)>> {
    let mut reader: Reader<&[u8]> = Reader::from_reader(data);
    reader.trim_text(true);

    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(4096);
    let mut current_start: Option<usize> = None;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let start_pos: usize = reader.buffer_position();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"ReportHost" => {
                current_start = Some(start_pos);
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"ReportHost" => {
                if let Some(start) = current_start {
                    ranges.push((start, reader.buffer_position()));
                    current_start = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML syntax error: {}", e)),
            _ => {}
        }
        buf.clear();
    }
    Ok(ranges)
}