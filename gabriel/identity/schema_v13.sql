CREATE TABLE gabriel_identity.case_assignments (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    request_id uuid NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 128),
    assigned_to uuid,
    assigned_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,request_id),
    UNIQUE (organization_id,case_id,sequence),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,assigned_to) REFERENCES gabriel_identity.memberships(organization_id,user_id),
    FOREIGN KEY (organization_id,assigned_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX case_assignment_target ON gabriel_identity.case_assignments(organization_id,assigned_to);
CREATE INDEX case_assignment_actor ON gabriel_identity.case_assignments(organization_id,assigned_by);
CREATE TABLE gabriel_identity.case_questions (
    organization_id uuid NOT NULL,
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    request_id uuid NOT NULL,
    question text NOT NULL CHECK (length(question) BETWEEN 1 AND 512),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,case_id,id),
    UNIQUE (organization_id,case_id,request_id),
    FOREIGN KEY (organization_id,case_id) REFERENCES gabriel_identity.cases(organization_id,id),
    FOREIGN KEY (organization_id,created_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX case_question_actor ON gabriel_identity.case_questions(organization_id,created_by);
CREATE TABLE gabriel_identity.case_question_answers (
    organization_id uuid NOT NULL,
    question_id uuid NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    answer text NOT NULL CHECK (length(answer) BETWEEN 1 AND 1024),
    answered_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,question_id),
    FOREIGN KEY (organization_id,case_id,question_id) REFERENCES gabriel_identity.case_questions(organization_id,case_id,id),
    FOREIGN KEY (organization_id,case_id,evidence_id) REFERENCES gabriel_identity.evidence_objects(organization_id,case_id,id),
    FOREIGN KEY (organization_id,answered_by) REFERENCES gabriel_identity.memberships(organization_id,user_id)
);
CREATE INDEX case_answer_question ON gabriel_identity.case_question_answers(organization_id,case_id,question_id);
CREATE INDEX case_answer_evidence ON gabriel_identity.case_question_answers(organization_id,case_id,evidence_id);
CREATE INDEX case_answer_actor ON gabriel_identity.case_question_answers(organization_id,answered_by);
REVOKE ALL ON gabriel_identity.case_assignments,gabriel_identity.case_questions,gabriel_identity.case_question_answers FROM PUBLIC;
GRANT SELECT,INSERT ON gabriel_identity.case_assignments,gabriel_identity.case_questions,gabriel_identity.case_question_answers TO gabriel_identity_app;
