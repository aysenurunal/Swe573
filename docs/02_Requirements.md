# Software Requirements Specification (SRS)

**Project:** The Hive — A Community-Oriented Service Offering Platform  
**Version:** 2.0  
**Date:** 21 October 2025  
**Prepared by:** Ayşenur Ünal  

---

## 1. Introduction

### 1.1 Purpose
This document defines the functional and non-functional requirements for *The Hive*, a community-oriented service exchange platform based on mutual support. It provides a comprehensive specification for designers, developers, and stakeholders to ensure consistent understanding of the system’s purpose and constraints.

### 1.2 Scope
The Hive is a virtual public space that enables users to offer and request community-based services through a fair and non-monetary system. It operates using a “TimeBank” model where every hour of service has equal value.  
The system supports:
- Posting offers and needs
- Searching via semantic tags and filters
- Negotiating and chatting after a “handshake”
- Managing earned and spent TimeBank hours
- Community moderation via an admin panel

The system will **not** include monetary transactions, user-to-user hour transfers, or strict identity verification.

### 1.3 Definitions, Acronyms, and Abbreviations
| Term | Definition |
|------|-------------|
| TimeBank | A virtual currency system where one hour of service equals one TimeBank hour. |
| Offer | A service posted by a user to provide help. |
| Need | A service request posted by a user. |
| Handshake | A mutual agreement between two users to exchange a service. |
| Admin | A user with special permissions for moderation and community management. |

### 1.4 References
- IEEE 830–1998 Software Requirements Specification Standard  
- Project description: *“The Hive: A Community-Oriented Service Offering Platform”* (Instructor document, 2025)  
- Course notes and elicitation session (October 2025)

### 1.5 Overview
Section 2 describes the system overview and context.  
Section 3 lists all specific requirements, divided into functional and non-functional groups.  
Section 4 includes appendices and glossary terms.

---

## 2. Overall Description

### 2.1 Product Perspective
The Hive is a web-based community platform designed as an open-source system. It functions independently but may integrate with public APIs such as Wikidata for semantic tagging. It will include modules for user management, service matching, negotiation, and admin oversight.

### 2.2 Product Functions
- Create and manage offers and needs on an interactive map  
- Search and filter services by tags, location, or keywords  
- Initiate negotiations and communicate via chat  
- Track and manage TimeBank hours  
- Enable admin users to moderate content and handle reports  

### 2.3 User Characteristics
| User Type | Description | Technical Skill |
|------------|--------------|-----------------|
| Guest | Can view public offers and needs | Low |
| Registered User | Can post, negotiate, chat, and earn/spend hours | Medium |
| Admin | Can manage community, warnings, and bans | High |

### 2.4 Constraints
- Services are measured in hours (minimum unit = 1 hour).  
- No monetary exchange or transfer of hours between users.  
- Users can initially register with 3 hours, with a limit of 10 unspent hours.  
- Some services may be online (virtual).  
- The system should comply with open-source license constraints.

### 2.5 Assumptions and Dependencies
- Users have internet access and modern web browsers.  
- Semantic tags are supported via Wikidata or local dictionary.  
- Community moderation depends on active admin participation.

---

## 3. Specific Requirements

### 3.1 Functional Requirements

| ID | Requirement | Priority | Notes |
|----|--------------|-----------|--------|
| 3.1.1 | The system shall allow users to register and receive 3 initial TimeBank hours. | High | First-time setup balance. |
| 3.1.2 | The system shall enforce a 10-hour upper limit before new offers can be created. | Medium | Encourages hour circulation. |
| 3.1.3 | The system shall allow users to create multiple offers for different services. | High | Example: 5 piano lessons = 5 separate posts. |
| 3.1.4 | The system shall allow users to specify expiration dates for offers and needs. | Medium | Prevents outdated listings. |
| 3.1.5 | The system shall provide semantic tagging for offers and needs. | High | Tags support searching and matching. |
| 3.1.6 | The system shall suggest recommendations even when no exact match is found. | Medium | Enhances user discovery. |
| 3.1.7 | The system shall allow filtering and searching using tags, keywords, and location. | High | Multi-criteria search functionality. |
| 3.1.8 | The system shall allow users to view offers and needs on an interactive map by province. | Medium | Location visibility after handshake. |
| 3.1.9 | The system shall enable public negotiation messages before a handshake. | High | Facilitates open communication. |
| 3.1.10 | The system shall provide private chat after a handshake. | High | Enables location sharing and details. |
| 3.1.11 | The system shall allow users to rate each other after completing a service. | Medium | Optional, may use label-like feedback. |
| 3.1.12 | The system shall allow admins to issue warnings or bans for reported users. | High | Admin moderation responsibility. |
| 3.1.13 | The system shall allow admins to make a user’s profile invisible upon serious violation. | High | Community safety enforcement. |
| 3.1.14 | The system shall store and display reports on indecent or spam behavior. | High | Supports transparency and moderation. |
| 3.1.15 | The system shall allow users to post both online and offline services. | Medium | Covers virtual offers. |
| 3.1.16 | The system shall prevent hour transfers between users. | High | Keeps fairness in the TimeBank model. |
| 3.1.17 | The system shall allow admins to view overall statistics and flagged users. | Medium | Part of admin panel dashboard. |
| 3.1.18 | The system shall support multi-language semantic search (via Wikidata integration). | Medium | “cat = pisi pisi = animal”. |

---

### 3.2 Non-Functional Requirements

| Category | Requirement | Priority |
|-----------|--------------|-----------|
| Performance | The system should respond to user actions (search, post, chat) within 3 seconds. | High |
| Security | All communications shall be encrypted via HTTPS. | High |
| Security | Only admins can delete or hide user profiles. | High |
| Reliability | The system shall ensure data persistence and backup for all user activities. | High |
| Usability | The interface shall be accessible on both mobile and desktop devices. | Medium |
| Usability | Semantic tags should auto-suggest as the user types. | Medium |
| Maintainability | Code shall be modular, documented, and version-controlled (Git). | High |
| Scalability | The platform shall support at least 1,000 concurrent users. | Medium |
| Portability | The system shall run on major browsers (Chrome, Firefox, Safari, Edge). | High |
| Ethics | The platform shall comply with open community and non-commercial principles. | High |

---

### 3.3 Database Requirements
- Each user shall have a profile containing name, available hours, and history of exchanges.  
- Each offer/need entry shall include: title, description, tags, location, and expiration date.  
- Ratings and reports shall be stored with reference to user IDs and service IDs.

---

### 3.4 Design Constraints
- Open-source design, no proprietary dependencies.  
- Should follow RESTful API design for data exchange.  
- Use semantic tagging via Wikidata or internal ontology.

---

## 4. Appendices

### 4.1 Glossary
| Term | Description |
|------|--------------|
| Handshake | Agreement between users to exchange a service. |
| Tag | A keyword describing the type of service. |
| Admin Panel | Interface for moderation and analytics. |
| TimeBank Hour | Currency equivalent to one hour of service. |

### 4.2 Supporting Information
- Possible UI mockups for offer/need posting and map visualization.  
- Sequence diagram for “Handshake → Private Chat → Rating” flow.  

---

**End of Document**
