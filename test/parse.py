from fast_nessus_parser import NessusParser

parser = NessusParser("mock_scan.nessus")
data = parser.parse()

data.as_df().to_csv("output.csv", index=False)
