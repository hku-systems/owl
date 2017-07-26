# MySQL-24988 Testing w/ TSAN Build Tips
 * Install sysbench: `sudo apt-get install sysbench`
 * Create symlink: `sudo ln -s /tmp/mysql.sock /var/run/mysqld/mysqld.sock`
 * Setup mysql by typing `./setup.sh`
 * Run sysbench by typing `./sysbench.sh`.  Output should be in `output/tsan.[PID]`
 * Or to use bug triggering input, run `./client1.sh` and `./client2.sh`

