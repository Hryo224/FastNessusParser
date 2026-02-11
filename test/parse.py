from fast_nessus_parser import NessusParser

parser = NessusParser("mock_scan.nessus")
data = parser.parse()

data.to_pandas().to_csv("output.csv", index=False)
