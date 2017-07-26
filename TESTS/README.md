# Run Guide
To generate TSAN reports, type `./run.sh no_static_analysis` in the application's directory (eg. `apache-21287/`).  TSAN reports will be outputted to the `output/` directory in the application's directory.  Please ensure that the specific applications you want to test are built in the `concurrency-exploits/` directory before running our script.

Please note that some `run.sh` scripts were copied from other applications so the `no_race_detector` flag is not guaranteed to work on most applications.
