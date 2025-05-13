-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 12, 2025 at 11:32 PM
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
-- Database: `securedocs_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `alembic_version`
--

CREATE TABLE `alembic_version` (
  `version_num` varchar(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `alembic_version`
--

INSERT INTO `alembic_version` (`version_num`) VALUES
('bf20e4b5682f');

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `timestamp` datetime DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `action_type` varchar(100) NOT NULL,
  `target_user_id` int(11) DEFAULT NULL,
  `target_document_id` int(11) DEFAULT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `request_method` varchar(10) DEFAULT NULL,
  `resource_path` varchar(255) DEFAULT NULL,
  `referer` varchar(512) DEFAULT NULL,
  `http_version` varchar(10) DEFAULT NULL,
  `status_code` int(11) DEFAULT NULL,
  `response_size` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `timestamp`, `user_id`, `action_type`, `target_user_id`, `target_document_id`, `details`, `ip_address`, `user_agent`, `request_method`, `resource_path`, `referer`, `http_version`, `status_code`, `response_size`) VALUES
(1, '2025-05-12 21:23:45', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 10386),
(2, '2025-05-12 21:23:47', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 14579),
(3, '2025-05-12 21:26:09', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/', NULL, 'HTTP/1.1', 302, 207),
(4, '2025-05-12 21:26:10', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/dashboard\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/dashboard', NULL, 'HTTP/1.1', 200, 7581),
(5, '2025-05-12 21:26:11', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin', 'https://127.0.0.1:5000/dashboard', 'HTTP/1.1', 200, 7405),
(6, '2025-05-12 21:26:13', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 27205),
(7, '2025-05-12 21:28:17', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin/audit_logs', 'HTTP/1.1', 200, 29174),
(8, '2025-05-12 21:28:21', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin/audit_logs', 'HTTP/1.1', 200, 32339),
(9, '2025-05-12 21:29:32', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/', NULL, 'HTTP/1.1', 302, 207),
(10, '2025-05-12 21:29:32', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/dashboard\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/dashboard', NULL, 'HTTP/1.1', 200, 7581),
(11, '2025-05-12 21:29:34', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin', 'https://127.0.0.1:5000/dashboard', 'HTTP/1.1', 200, 7405),
(12, '2025-05-12 21:29:36', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 44799),
(13, '2025-05-12 21:29:39', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 47951),
(14, '2025-05-12 21:29:42', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 51103),
(15, '2025-05-12 21:29:45', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 54255),
(16, '2025-05-12 21:30:36', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 54632),
(17, '2025-05-12 21:31:02', 1, 'REQUEST_SERVED_GET', NULL, NULL, '{\n  \"path\": \"/admin/audit_logs\",\n  \"args\": {}\n}', '127.0.0.1', NULL, 'GET', '/admin/audit_logs', 'https://127.0.0.1:5000/admin', 'HTTP/1.1', 200, 57543);

-- --------------------------------------------------------

--
-- Table structure for table `documents`
--

CREATE TABLE `documents` (
  `id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `saved_filename` varchar(255) NOT NULL,
  `filesize` int(11) NOT NULL,
  `filetype` varchar(50) DEFAULT NULL,
  `upload_date` datetime DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `sha256_hash` varchar(64) DEFAULT NULL,
  `is_encrypted` tinyint(1) DEFAULT NULL,
  `digital_signature` text DEFAULT NULL,
  `encrypted_filesize` int(11) DEFAULT NULL,
  `encryption_salt` tinyblob DEFAULT NULL,
  `encryption_nonce` tinyblob DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `documents`
--

INSERT INTO `documents` (`id`, `filename`, `saved_filename`, `filesize`, `filetype`, `upload_date`, `user_id`, `sha256_hash`, `is_encrypted`, `digital_signature`, `encrypted_filesize`, `encryption_salt`, `encryption_nonce`) VALUES
(2, 'README.md.pdf', '5f5421c5c1a045d29cdcbf4f651963d1.pdf.enc', 326236, 'pdf', '2025-05-12 02:08:49', 8, '7811d41bc1fbc8774570c55cf00902c5c757555a78fb3a6811793ab131af39b9', 1, 'ki9JtfB7WMFqXUFtq5PkyNxMOU58kPq361YsJkF7d8XTPlmO78RVn83z5w23DqwpcCHaHQodBTkr5zZIepIn4au/bmgfL1eZNtnzg03sP4G4ubNS3KGu1LhD57ahAb7K55WJ8w+cU2JaYcdmNarp7cJl7/tPujutC5JVVLPWZTfj7XLTNOhGsdBTFR5ZqFx2ZTRt5EoFcSq+IO9ldV4HJRtqIzzIkEeMB0OMx2xdle9rZmFCzm9B2FvnSUaeOIKBDQwCLJS8XKeOANY+oux+AYdHJJqHkxvEKg7JWirgHP55rmsB3d+Qox+U7+0VDpXIIxbgTla0A5lLZwB6P4uLRQ==', 326252, 0xbb00ba280bc9b67f914854ab7cff94ff, 0xb7a39ffc729d2d0c3a505e7f),
(3, 'README.md.pdf', '9b705d7bba144442a54f4a4170615eaa.pdf.enc', 326236, 'pdf', '2025-05-12 21:03:49', 8, '7811d41bc1fbc8774570c55cf00902c5c757555a78fb3a6811793ab131af39b9', 1, 'AsbP6wv8YX0kT9DwejLhX3Hk0n4mXLTCSEiQKQwHF7nhqOSdZmAx8z4pha3B16XKha5bHld5OrtfyJ8nAlneVuEHat8Go7VAHg1o9vU6/0u1hJPGaC+3amFQJC82iv0xVpxEIpwHiApL1nvKqy6251bTeTrXByyEbDOgfabcZFbMlUinMwPUV9SyckgM1T9dgsFXQtMnsWd8oHvtQiEX/Pk+3iDq0hi3B2fPM7Y4lHmPPJJC9+sxEchEixHPFrdYZMZnCRYrFPk4C7ti/1sUEhtaZnBqFKt1AQcqcQ2U94vTewRsKlJftqSwe3ynr9HTTEpQL+uVnSzIaOBtP2bk2w==', 326252, 0x00c75161afbbdcb64293f27dacc45403, 0xf46f68df2001c16b9d364660),
(4, 'Essay_6-2.pdf', '80a39c3b93684fba8077bcd741cc7554.pdf.enc', 809067, 'pdf', '2025-05-12 21:08:51', 1, '081d63352c9f4cdbed969b10a3d55a3c95f5434ffcb61b9ddd59fa051ce67144', 1, 'K1QjttuZ4HoFqTVQlLWWZmWof6g+NWGed51wcNacprv1UOeJzGldPOC+Qq+JZcxWJRw5irGQq4tAumU8k2Jb659L2G2p2yhROS9dKf9vCp20sa0eT8mCi3hNO641BAhafi8QuhLOghgTa4aO1nCt6kqpy6hp1Cr7sZmiMXOhOTV+lPw+kRHYvAfO70AhYrttMcgYq5+9v0FO8ExiorFA0FERzSVbW+8860U8GxrBj+u2drYEKaNwULstPPXDqAmV4qRr1aH1yDcvlvD1xkK0dQViQn56/a9SmVJiNOkxHcicWR/zDM5WRXYNg/UJxtHPskp7LLHWb/n1u3vcnQYQ6Q==', 809083, 0x6ee6e7d903918c6b8fa23cf3f0b486c0, 0xff8273fced2c559177b67e30);

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(150) NOT NULL,
  `name` varchar(150) DEFAULT NULL,
  `role` varchar(50) NOT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `oauth_provider` varchar(50) DEFAULT NULL,
  `oauth_uid` varchar(255) DEFAULT NULL,
  `otp_secret` varchar(100) DEFAULT NULL,
  `is_2fa_enabled` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `email`, `name`, `role`, `password_hash`, `oauth_provider`, `oauth_uid`, `otp_secret`, `is_2fa_enabled`, `created_at`, `updated_at`) VALUES
(1, 'admin@admin.com', 'admin', 'admin', 'scrypt:32768:8:1$7OXgRnCBkFhqaF9e$d2e262657af3b5a17c263dc6fa6d1c27a2eff08a0de4a3ea52803bdac0367d1dcd64b4ba79d8dfd64f0050d0a2834caba8ee2adab0e3551ec90339d7a1a541c2', NULL, NULL, 'B3WQMLQULWLZQJ2OCZXF7E2ORYSMQKRG', 0, '2025-05-11 13:48:42', '2025-05-11 14:46:21'),
(8, 'aghazal085@gmail.com', 'Ahmed Ghazal', 'user', NULL, 'okta', 'google-oauth2|114435797521732525747', NULL, 0, '2025-05-12 02:08:25', '2025-05-12 02:08:25'),
(9, 'aghazalll070@gmail.com', 'Ah Gh', 'user', NULL, 'okta', 'google-oauth2|110265995016311641357', NULL, 0, '2025-05-12 20:18:06', '2025-05-12 20:18:06'),
(10, 'test@gmail.com', 'test', 'user', 'scrypt:32768:8:1$owHuQG52yvwxaaT3$7683d16713230615d3038e68371110d49cfe07e1fdbcf2b37302e656209da98788c13db5c271c1980359efc6cd3cf86f0174ff3fc5e019543d9c2e16e28429de', NULL, NULL, NULL, 0, '2025-05-12 20:54:01', '2025-05-12 20:54:01');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `alembic_version`
--
ALTER TABLE `alembic_version`
  ADD PRIMARY KEY (`version_num`);

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `target_user_id` (`target_user_id`),
  ADD KEY `target_document_id` (`target_document_id`);

--
-- Indexes for table `documents`
--
ALTER TABLE `documents`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `saved_filename` (`saved_filename`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `uq_oauth_provider_uid` (`oauth_provider`,`oauth_uid`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `documents`
--
ALTER TABLE `documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD CONSTRAINT `audit_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `audit_logs_ibfk_2` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `audit_logs_ibfk_3` FOREIGN KEY (`target_document_id`) REFERENCES `documents` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `documents`
--
ALTER TABLE `documents`
  ADD CONSTRAINT `documents_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
