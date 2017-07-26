Create database if not exists db1;
Create table if not exists db1.t1 (id int);
GRANT SELECT ON db1.t1 TO 'bugtest'@'localhost';
