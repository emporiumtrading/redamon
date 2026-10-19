"""Audited ownership and evidence-linked analyst comments; never grants authority or learned truth."""
from uuid import uuid4
from gabriel.identity.cases import iso
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,connection,identifier


def text(value,limit):
    if not isinstance(value,str) or not 1<=len(value.strip())<=limit or any(ord(c)<32 or ord(c)==127 for c in value):
        raise InvalidIdentityInput('invalid_investigation_text')
    try: value.encode('utf-8')
    except UnicodeError: raise InvalidIdentityInput('invalid_investigation_text') from None
    return value.strip()


def assignment_row(row):
    return dict(id=str(row['id']),case_id=str(row['case_id']),request_id=str(row['request_id']),sequence=row['sequence'],
        assigned_to=str(row['assigned_to']) if row['assigned_to'] else None,assigned_by=str(row['assigned_by']),created_at=iso(row['created_at']))


def assign_case(service,token,case_id,request_id,assigned_to):
    request_id=identifier(request_id)
    assigned_to=identifier(assigned_to) if assigned_to is not None else None
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        previous=conn.execute('''SELECT * FROM gabriel_identity.case_assignments
            WHERE organization_id=%s AND case_id=%s ORDER BY sequence DESC LIMIT 1''',(p.organization_id,case['id'])).fetchone()
        if p.role not in {'owner','admin'} and (assigned_to!=p.user_id or (previous and previous['assigned_to'] not in {None,p.user_id})):
            raise AccessDenied('assignment_not_permitted')
        if assigned_to:
            member=conn.execute('''SELECT m.role FROM gabriel_identity.memberships m JOIN gabriel_identity.users u
                ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE m.organization_id=%s AND m.user_id=%s AND m.active AND u.active AND m.role IN ('owner','admin','analyst')''',
                (p.organization_id,assigned_to)).fetchone()
            if not member: raise AccessDenied('assignee_not_accessible')
        replay=conn.execute('''SELECT * FROM gabriel_identity.case_assignments
            WHERE organization_id=%s AND case_id=%s AND request_id=%s''',(p.organization_id,case['id'],request_id)).fetchone()
        if replay:
            if replay['assigned_to']!=assigned_to or replay['assigned_by']!=p.user_id: raise AccessDenied('assignment_request_conflict')
            return assignment_row(replay)
        sequence=previous['sequence']+1 if previous else 1
        if sequence>128: raise AccessDenied('case_assignment_limit')
        row=conn.execute('''INSERT INTO gabriel_identity.case_assignments
            (organization_id,id,case_id,request_id,sequence,assigned_to,assigned_by) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
            (p.organization_id,uuid4(),case['id'],request_id,sequence,assigned_to,p.user_id)).fetchone()
        _audit(conn,'case.assigned',p,case['id'])
        return assignment_row(row)


def add_question(service,token,case_id,request_id,question):
    question,request_id=text(question,512),identifier(request_id)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        row=conn.execute('''SELECT * FROM gabriel_identity.case_questions
            WHERE organization_id=%s AND case_id=%s AND request_id=%s''',(p.organization_id,case['id'],request_id)).fetchone()
        if row:
            if row['question']!=question or row['created_by']!=p.user_id: raise AccessDenied('question_request_conflict')
            return str(row['id'])
        count=conn.execute('SELECT count(*) AS n FROM gabriel_identity.case_questions WHERE organization_id=%s AND case_id=%s',
            (p.organization_id,case['id'])).fetchone()['n']
        if count>=64: raise AccessDenied('case_question_limit')
        question_id=uuid4()
        conn.execute('''INSERT INTO gabriel_identity.case_questions
            (organization_id,id,case_id,request_id,question,created_by) VALUES (%s,%s,%s,%s,%s,%s)''',
            (p.organization_id,question_id,case['id'],request_id,question,p.user_id))
        _audit(conn,'case.question_added',p,case['id'])
        return str(question_id)


def answer_question(service,token,case_id,question_id,evidence_id,answer):
    answer,question_id,evidence_id=text(answer,1024),identifier(question_id),identifier(evidence_id)
    with connection(service._dsn) as conn:
        p=service._human(conn,token,write=True)
        case=service._case(conn,p,case_id,open_only=True)
        question=conn.execute('''SELECT id FROM gabriel_identity.case_questions
            WHERE organization_id=%s AND case_id=%s AND id=%s''',(p.organization_id,case['id'],question_id)).fetchone()
        if not question: raise AccessDenied('question_not_accessible')
        evidence=service._evidence(conn,p,evidence_id)
        if evidence['case_id']!=case['id']: raise AccessDenied('case_evidence_not_accessible')
        service._verify(conn,evidence)
        row=conn.execute('''SELECT * FROM gabriel_identity.case_question_answers
            WHERE organization_id=%s AND question_id=%s''',(p.organization_id,question_id)).fetchone()
        if row:
            if row['answer']!=answer or row['evidence_id']!=evidence_id or row['answered_by']!=p.user_id: raise AccessDenied('answer_already_recorded')
            return {'question_id':str(question_id),'state':'human_answer_supplied','source_verified':False}
        conn.execute('''INSERT INTO gabriel_identity.case_question_answers
            (organization_id,question_id,case_id,evidence_id,answer,answered_by) VALUES (%s,%s,%s,%s,%s,%s)''',
            (p.organization_id,question_id,case['id'],evidence_id,answer,p.user_id))
        _audit(conn,'case.question_answered',p,case['id'])
        return {'question_id':str(question_id),'state':'human_answer_supplied','source_verified':False}


def case_workflow(service,token,case_id):
    with connection(service._dsn) as conn:
        p=service._human(conn,token)
        case=service._case(conn,p,case_id)
        assignments=conn.execute('''SELECT * FROM gabriel_identity.case_assignments
            WHERE organization_id=%s AND case_id=%s ORDER BY sequence LIMIT 129''',(p.organization_id,case['id'])).fetchall()
        questions=conn.execute('''SELECT q.*,a.answer,a.evidence_id,a.answered_by,a.created_at AS answered_at
            FROM gabriel_identity.case_questions q LEFT JOIN gabriel_identity.case_question_answers a
            ON (a.organization_id,a.case_id,a.question_id)=(q.organization_id,q.case_id,q.id)
            WHERE q.organization_id=%s AND q.case_id=%s ORDER BY q.created_at,q.id LIMIT 65''',(p.organization_id,case['id'])).fetchall()
        if len(assignments)>128 or len(questions)>64: raise AccessDenied('case_workflow_limit')
        current=assignment_row(assignments[-1]) if assignments else None
        if current and current['assigned_to']:
            member=conn.execute('''SELECT m.active,m.role,u.active AS user_active FROM gabriel_identity.memberships m
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE m.organization_id=%s AND m.user_id=%s''',(p.organization_id,identifier(current['assigned_to']))).fetchone()
            current['assignee_active']=bool(member and member['active'] and member['user_active'] and member['role']!='viewer')
        return dict(case_id=str(case['id']),assignment=current,assignment_history=[assignment_row(row) for row in assignments],
            questions=[dict(id=str(row['id']),question=row['question'],created_by=str(row['created_by']),created_at=iso(row['created_at']),
                state='human_answer_supplied' if row['answer'] is not None else 'open',answer=row['answer'],
                evidence_id=str(row['evidence_id']) if row['evidence_id'] else None,answered_by=str(row['answered_by']) if row['answered_by'] else None,
                answered_at=iso(row['answered_at']),source_verified=False) for row in questions] if p.role!='viewer' else [],
            questions_restricted=p.role=='viewer',
            knowledge_status='analyst_comments_not_validated_memory',assignment_grants_authority=False)
