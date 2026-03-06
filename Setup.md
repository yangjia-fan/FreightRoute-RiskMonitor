In **Mac Terminal** or **Windows Shell**

Run the following:

### Step 1: Download the repo

	git clone https://github.com/yangjia-fan/FreightRoute-RiskMonitor.git
	
	cd FreightRoute-RiskMonitor

### Step 2: Create + activate virtual environment

Mac Terminal:
	
	python3 -m venv .venv

	source .venv/bin/activate

Windows Shell:

	py -m venv .venv
	
	.\.venv\Scripts\Activate.ps1


### Step 3: Install dependencies

	pip install -r requirements.txt


### Step 4: Run the app

	uvicorn app:app --host 127.0.0.1 --port 8787 --reload


### Step 5: Open in Browser

Using:

	http://127.0.0.1:8787/
