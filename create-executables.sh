
rm -rf ./dist/

pyinstaller --onefile --noconsole --add-data="src/risklesspain/*:." src/risklesspain/main.py
echo "Starting ./dist/main"
./dist/main


#cxfreeze -c src/risklesspain/main.py --target-dir dist