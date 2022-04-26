CREATE TABLE cg_users (
  user_id UUID PRIMARY KEY,
  email varchar(320) UNIQUE NOT NULL,
  refresh_token varchar(64) UNIQUE,
  starling_uid UUID,
  password_hash bytea NOT NULL,
  confirmed_email boolean default false,
  account_created timestamp DEFAULT CURRENT_TIMESTAMP,
);

CREATE TABLE event_log (
  batch_id UUID PRIMARY KEY,
  user_id UUID REFERENCES cg_users(user_id) NOT NULL,
  event_timestamp timestamp NOT NULL,
  added_to_db smallint NOT NULL,
  error_count smallint NOT NULL
);

CREATE TABLE tx_dataset (
  tx_id UUID PRIMARY KEY, -- from Starling
  batch_id UUID REFERENCES event_log(batch_id) NOT NULL,
  amount_in_pence int NOT NULL,
  category varchar(32) NOT NULL,
  company varchar(96) NOT NULL,
  user_id UUID REFERENCES cg_users(user_id) NOT NULL,
  tx_timestamp timestamp DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_tracking (
  user_id UUID REFERENCES cg_users(user_id) PRIMARY KEY,
  carbon_emitted_kg real,
  carbon_balanced_kg real,
  spent_to_date integer
);

CREATE TABLE user_payments(
  payment_order_uid UUID  PRIMARY KEY, -- from Starling
	user_id UUID REFERENCES cg_users(user_id),
  offset_amount_pence int NOT NULL,
  fee_pence int NOT NULL,
  date_paid timestamp DEFAULT CURRENT_TIMESTAMP,
  offset_purchased boolean DEFAULT false,
	offset_date timestamp,
  offset_reference varchar(50)
);
