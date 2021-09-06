CREATE TABLE user (
	username VARCHAR(80) PRIMARY KEY,
	ukey VARCHAR(20),
	display_name VARCHAR(160),
	rp_id VARCHAR(253),
	icon_url VARCHAR(2083)
);

CREATE TABLE credential (
	cred_id VARCHAR(250) PRIMARY KEY,
	username VARCHAR(80),
	pub_key VARCHAR(65),
	sign_count INTEGER,
	can_delete_creds BOOLEAN,
	can_add_creds BOOLEAN,
	FOREIGN KEY (username) REFERENCES user(username)
);
