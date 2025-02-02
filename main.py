from flask import Flask, render_template, request
import requests
from collections import Counter
import pandas as pd

app = Flask(__name__)

API_KEY = "fcb15d5e2eafdf431789614a30f2ace9ed7e64e421d77b4d7402511a41c98226"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
FILE_URL = "https://www.virustotal.com/api/v3/files"

headers = {
    "accept": "application/json",
    "x-apikey": API_KEY
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/url", methods=["GET", "POST"])
def url_page():
    scan_results = None

    if request.method == "POST":
        user_url = request.form.get("url")

        # Submit URL for scanning
        payload = {"url": user_url}
        response = requests.post(VIRUSTOTAL_URL, data=payload, headers=headers)
        scan_data = response.json()

        scan_id = scan_data.get("data", {}).get("id")

        if scan_id:
            # Retrieve scan results
            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            response = requests.get(report_url, headers=headers)
            report_data = response.json()

            if "data" in report_data:
                category_count = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}
                categories = []
                results = []
                print(report_data)
                for data in report_data["data"]["attributes"]["results"].values():
                    category = data.get("category", "unknown")
                    result = data.get("result")

                    if category in category_count:
                        category_count[category] += 1
                    categories.append(category)
                    if result:
                        results.append(result)

                total_companies = len(report_data["data"]["attributes"]["results"])
                majority_category = Counter(categories).most_common(1)
                majority_result = Counter(results).most_common(1)

                scan_results = {
                    "url": user_url,
                    "category_count": category_count,
                    "total_companies": total_companies,
                    "majority_category": majority_category[0][0] if majority_category else "No majority",
                    "majority_result": majority_result[0][0] if majority_result else "No majority"
                }

    return render_template("url.html", scan_results=scan_results)


@app.route("/document", methods=["GET", "POST"])
def document_page():
    scan_results = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file:
            # Prepare the file for upload
            files = {"file": (uploaded_file.filename, uploaded_file.stream, uploaded_file.content_type)}

            # Make the API request
            response = requests.post(FILE_URL, files=files, headers=headers)

            # Print the raw JSON response in the terminal
            print(response.json())  # This will print the entire response JSON to the terminal

            # Parse the response and proceed with analysis (same as before)
            if response.status_code == 200:
                scan_data = response.json()
                scan_id = scan_data.get("data", {}).get("id")

                if scan_id:
                    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
                    response = requests.get(report_url, headers=headers)
                    report_data = response.json()

                    # Print the JSON of the detailed analysis response as well
                    print(report_data)  # This will print the detailed analysis response

                    if "data" in report_data:
                        category_count = {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}
                        categories = []
                        results = []

                        for data in report_data["data"]["attributes"]["results"].values():
                            category = data.get("category", "unknown")
                            result = data.get("result")

                            if category in category_count:
                                category_count[category] += 1
                            categories.append(category)
                            if result:
                                results.append(result)

                        total_companies = len(report_data["data"]["attributes"]["results"])
                        majority_category = Counter(categories).most_common(1)
                        majority_result = Counter(results).most_common(1)

                        scan_results = {
                            "file_name": uploaded_file.filename,
                            "category_count": category_count,
                            "total_companies": total_companies,
                            "majority_category": majority_category[0][0] if majority_category else "No majority",
                            "majority_result": majority_result[0][0] if majority_result else "No majority"
                        }

    return render_template("document.html", scan_results=scan_results)


@app.route("/upload_csv", methods=["GET", "POST"])
def upload_csv():
    extracted_data = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file and uploaded_file.filename.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
            extracted_data = df.to_dict(orient="records")  # Convert rows to dictionaries

    return render_template("csv.html", data=extracted_data)


if __name__ == "__main__":
    app.run(debug=True)