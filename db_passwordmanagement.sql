-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 20, 2024 at 05:44 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `db_passwordmanagement`
--

-- --------------------------------------------------------

--
-- Table structure for table `password_stored`
--

CREATE TABLE `password_stored` (
  `id` int(100) NOT NULL,
  `website_name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `password_stored`
--

INSERT INTO `password_stored` (`id`, `website_name`, `email`, `password`) VALUES
(10, 'www.edwin.com', 'edwin@gmail.com', 'Whm+N=8C3?!0');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `email`, `password`) VALUES
(1, 'edwin@gmail.com', '$2b$12$wQEIcC8HhHal7MspIvP1suxT2EKJZk4VBTf/4YPh7hb5RSJFo6dyG'),
(2, 'jiawei@gmail.com', '$2b$12$HTThNRbX6/in/N.5MYkWgut1Tavd.x4zmLpa3esUN7C5dJi61ezr2'),
(3, 'edwinchia0710@gmail.com', '$2b$12$NsuBr2X60V0qJQERBSKTCuHu1M83LSod1j8UP5VD6XDY.BvWu17Eu');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `password_stored`
--
ALTER TABLE `password_stored`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `password_stored`
--
ALTER TABLE `password_stored`
  MODIFY `id` int(100) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(100) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;


-- pip install Flask-Bcrypt

-- pip install Flask-MySQLdb
-- # or
-- pip install mysql-connector-python
