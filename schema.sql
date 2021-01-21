-- Create Database
CREATE DATABASE mentor_platform;

-- Mentee Table
CREATE TABLE mentee(
    id uuid PRIMARY KEY DEFAULT
    uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    linkedin VARCHAR (255),
    reset_token VARCHAR(255)
);

-- Mentor Table
CREATE TABLE mentor(
    id uuid PRIMARY KEY DEFAULT 
    uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    job_title VARCHAR (255),
    company VARCHAR (255),
    category VARCHAR (255),
    tags TEXT[],
    price VARCHAR(255),
    experience VARCHAR (255),
    college VARCHAR (255),
    bio VARCHAR (255),
    mobile_number VARCHAR(10),
    profile_picture VARCHAR (255),
    linkedin VARCHAR (255),
    date_time text[],
    status BOOLEAN DEFAULT false,
    reset_token VARCHAR(255)
);

-- Call Table
CREATE TABLE book_call(
    id uuid PRIMARY KEY DEFAULT
    uuid_generate_v4(),
    mentor_id uuid,
    mentee_id uuid,
    dates_time VARCHAR(255), 
    booking_status VARCHAR (255),
    CONSTRAINT fk_mentor
      FOREIGN KEY(mentor_id) 
	  REFERENCES mentor(id)
	  ON DELETE CASCADE,
    CONSTRAINT fk_mentee
      FOREIGN KEY(mentee_id) 
	  REFERENCES mentee(id)
	  ON DELETE CASCADE
);

-- Insert Query
INSERT INTO tablename (fieldname, fieldname, ... )  
VALUES ('', '', '', ...);

-- Drop Table
DROP TABLE tablename;
