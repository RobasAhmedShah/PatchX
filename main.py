import requests
import pandas as pd
from bs4 import BeautifulSoup
import streamlit as st
import google.generativeai as genai
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Set up logging
logging.basicConfig(filename='vulnerability_logs.log', level=logging.INFO, 
                    format='%(asctime)s:%(levelname)s:%(message)s')

def search_vulnerabilities(software):
    url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={software}&search_type=all&isCpeNameSearch=false"
    response = requests.get(url)
    vulnerabilities = []
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find('table', class_='table table-striped table-hover')
        if table:
            rows = table.find('tbody').find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    vuln_id = row.find('a', href=True).text.strip()
                    summary = cells[0].find('p').text.strip()
                    cvss_severity = cells[1].find('em').text.strip()
                    vulnerabilities.append({'Vuln ID': vuln_id, 'Summary': summary, 'CVSS Severity': cvss_severity})
                    logging.info(f"Vulnerability ID: {vuln_id}, Summary: {summary}, CVSS Severity: {cvss_severity}")
    else:
        st.error("Failed to fetch data from the NVD website")
        logging.error("Failed to fetch data from NVD for software: " + software)
    return vulnerabilities
    api_key=os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    prompt = "Provide me with steps to fix the vulnerability described as follows: " + vulnerability_summary
    try:
        response = model.generate_content(prompt)
        return response.candidates[0].content.parts[0].text
    except Exception as e:
        logging.error(f"Failed to generate patch recommendation due to an error: {e}")
        return f"Failed to generate patch recommendation due to an error: {e}"
def patch_recommendation(vulnerability_summary):
    api_key=os.getenv("GOOGLE_API_KEY")
    print(api_key)
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    prompt = "Provide me with steps to fix the vulnerability described as follows: " + vulnerability_summary
    try:
        response = model.generate_content(prompt)
        return response.candidates[0].content.parts[0].text
    except Exception as e:
        logging.error(f"Failed to generate patch recommendation due to an error: {e}")
        return f"Failed to generate patch recommendation due to an error: {e}"
def show_logs():
    with open('vulnerability_logs.log', 'r') as log_file:
        log_data = log_file.read()
        st.text_area("Log Output", log_data, height=300)

def main():
    st.title('Software Vulnerability Finder and Patcher')
    software = st.text_input('Enter the software name:', '')
    
    if software:
        with st.spinner('Searching for vulnerabilities...'):
            vulnerabilities = search_vulnerabilities(software)
            if vulnerabilities:
                df = pd.DataFrame(vulnerabilities)
                st.subheader("Identified Vulnerabilities")
                st.dataframe(df)
                
                expander = st.expander("View Recommendations")
                with expander:
                    for _, row in df.iterrows():
                        summary = row['Summary']
                        vuln_id = row['Vuln ID']
                        patch_info = patch_recommendation(summary)
                        st.write(f"**Vulnerability ID:** {vuln_id}")
                        st.info(patch_info)

    if st.button('Show Logs'):
        show_logs()

if __name__ == "__main__":
    main()
