# ITS69404 CCA Group Q - Mini-application

# Cyber Attack Explorer with CTI/CCI Capabilities

The **Cyber Attack Explorer** is an interactive Streamlit application designed to help cybersecurity analysts visualize, explore, and interpret cyber attack datasets. It enhances traditional data exploration with **Cyber Threat Intelligence (CTI)** and **Cyber Counterintelligence (CCI)** capabilities, supporting modern security operations.

---

## 🚀 Features

### **1. CSV Upload & Automatic Column Detection**

* Upload any cyber attack dataset in `.csv` format.
* The system automatically detects common field names such as:

  * Date
  * Attack type
  * Severity
  * Target sector
  * Attack vector/method
* Shows dataset preview and metadata.

---

## 🛡 Tab 1: Latest Cyber Attacks

This section provides filtering and visualization capabilities for uploaded cyber attack data.

### **Key Features:**

* Filter attacks by:

  * Attack type
  * Severity
  * Date range
* Quick summary metrics:

  * Total attacks
  * High severity attacks
  * Recent activity (last 30 days)
* Displays filtered results using a clean and interactive table.

---

## 🔧 Tab 2: Security Measures

Shows a curated list of recommended cybersecurity measures inspired by industry sources.

### **Includes:**

* Priority-labelled action items (High / Medium).
* Checklist for implementation.
* Identification of measures related to **Counterintelligence (CCI)**.
* Summary metrics for:

  * Total measures
  * CCI-related measures
  * High-priority items

---

## 🕵️ Tab 3: CTI Analysis (Cyber Threat Intelligence)

Visual analytics to evaluate cyber attack trends.

### **Contains:**

* **Time-series analysis** of monthly attack frequency.
* **Attack type distribution** pie charts.
* **Target sector analysis** bar charts.
* **APT (Advanced Persistent Threat) Group Database:**

  * Country
  * Target industries
  * Common TTPs
  * Recommended mitigations
* **IOC Checker (Simulated):**

  * Search for IPs/domains/hashes.

---

## 🎯 Tab 4: CCI Operations (Cyber Counterintelligence)

Proactive counterintelligence tools and simulations.

### **Includes:**

* List of CCI deception & intelligence techniques.
* One-click deployment simulations (honeypots, misdirection, deception grids, etc.).
* Effectiveness metrics dashboard:

  * Detection rate
  * False positives
  * Attacker engagement
* Active CCI operation status panel
* Recommended CCI actions based on uploaded dataset’s attack patterns
* **CCI threat scenario simulation** (e.g., APT, ransomware, insider threat)

---

## 📂 How to Use

1. Run the Streamlit app:

   ```bash
   streamlit run app.py
   ```
2. Upload a CSV file containing cyber attack data.
3. Navigate through the tabs to analyze, visualize, and simulate responses.

---

## 📊 Example Dataset Structure

Your CSV should preferably contain columns like:

* `date`
* `attack_type`
* `severity`
* `sector`
* `vector`

However, the app automatically detects similar terms.

---

## 🧩 Requirements

* Python 3.8+
* Libraries:

  * `streamlit`
  * `pandas`
  * `plotly`
  * `numpy`

Install requirements:

```bash
pip install streamlit pandas plotly numpy
```

---

## 🛠 Future Enhancements

* Integration with real-time Threat Intelligence feeds (VirusTotal, MISP).
* Automated IOC scanning API.
* Attack graph visualization.
* AI-based threat prediction.

---

## 👨‍💻 Author

Built as a cybersecurity exploration tool focusing on CTI and CCI analytics.

---

## 📄 License

This project is provided for educational and research purposes.
