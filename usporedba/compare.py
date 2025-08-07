import pandas as pd
from ydata_profiling import ProfileReport


def compareLogs(factual_Log_path,Tool_Log_path,Comparison_Name):
    factual_Logs = pd.read_csv(factual_Log_path,sep="*")
    factual_Logs_report = ProfileReport(factual_Logs , title='Factual Data')
    FortiSIEM_Logs = pd.read_csv(Tool_Log_path,sep="*")
    FortiSIEM_Logs_report = ProfileReport(FortiSIEM_Logs, title='Custom Data')
    comparison_report = factual_Logs_report.compare(FortiSIEM_Logs_report)
    comparison_report.to_file(Comparison_Name)

compareLogs("FactualNormalCustomFolder.csv","CustomNormalFolder.csv","comparisonNormalCustomFolderPermission.html")
