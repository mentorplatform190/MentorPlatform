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
    tags VARCHAR (255),
    price INTEGER NOT NULL,
    experience VARCHAR (255),
    college VARCHAR (255),
    bio VARCHAR (255),
    profile_picture VARCHAR (255),
    linkedin VARCHAR (255),
    dates DATE, 
    time_slot DATE,
    status VARCHAR (255),
    reset_token VARCHAR(255)
);

-- Insert Query
INSERT INTO tablename (fieldname, fieldname, ... )  
VALUES ('', '', '', ...);

-- Drop Table
DROP TABLE tablename;
