Installation:
1. clone the project
2. inside root project directory: python3 -m venv venv
   - if you got error because not installed python3 venv yet, please install python3 venv & remove prevously created venv directory then repeat the step
3. run the virtual environment using command . venv/bin/activate
4. install postgresql 
5. adjust database connection at app.py line 11 and create a database named endpoints
6. pip install -r requirements.txt
7. flask db init
8. flask db upgrade
9. flask db migrate
10. to create seeder, execute: flask seeder 
11. to run the app: source activate.sh
