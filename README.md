# IDOR-vuln-report-Sample

Overview
Issue: We have identified an Insecure Direct Object Reference (IDOR) vulnerability affecting an
endpoint of the system. This vulnerability allows unauthorized users to access or manipulate
resources that they do not own or have permission to view, by modifying a reference to an
internal object- a user ID in the request.
By failing to enforce proper access controls at the object level, the application exposes sensi-
tive data and functionality to potential abuse. An attacker can exploit this flaw by iterating over
predictable identifiers or modifying object references in API requests, resulting in unauthorized
access to other users’ data or actions.
This report includes:
-A detailed explanation of the issue
-Steps to reproduce
-Risk assessment
