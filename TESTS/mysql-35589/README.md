# MySQL-34988 Testing w/ TSAN Build Tips
 * Install sysbench: `sudo apt-get install sysbench`
 * Create symlink: `sudo ln -s /tmp/mysql.sock /var/run/mysqld/mysqld.sock`
 * Setup mysql by typing `./setup.sh`
 * Sysbench currently hasn't been implemented for mysql-35988
 * To run bug triggering input, type `./run.sh`. Output should be in `output/tsan.[PID]`

