import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { authenticateSuperadmin } from './superadmin_routes.js';
import { sendTaskEmail, taskEmailTemplates } from '../services/taskEmail.service.js';
import { sendTaskAssignedWhatsApp } from '../services/agentVerification.service.js';
import logger from '../config/logger.js';

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────
const ok  = (res, data, message) => res.json({ success: true, data, message });
const bad = (res, status, message) => res.status(status).json({ success: false, message });

const getClientIp = (req) =>
  req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
  req.socket?.remoteAddress ||
  req.ip ||
  'unknown';

const logTaskAudit = async (superadminId, action, resourceId, reason, req) => {
  try {
    await supabase.from('superadmin_audit_logs').insert({
      superadmin_id: superadminId,
      action,
      resource_type: 'task',
      resource_id: String(resourceId),
      reason,
      status: 'success',
      error_message: '',
      ip_address: req ? getClientIp(req) : 'unknown',
      user_agent: req ? (req.get('user-agent') || 'unknown') : 'unknown',
    });
  } catch {
    // audit logging is best-effort — never block the actual task action
  }
};

// Only a task_manager can create/edit/assign/cancel tasks. req.superadmin is
// the full, freshly-queried row from authenticateSuperadmin, so this is a
// plain in-memory check — no extra DB round-trip.
function requireTaskManager(req, res, next) {
  if (req.superadmin?.task_role !== 'task_manager') {
    return bad(res, 403, 'Only a task manager can perform this action');
  }
  next();
}

async function getAdmin(id) {
  const { data, error } = await supabase
    .from('superadmin_credentials')
    .select('id, email, username, full_name, task_role')
    .eq('id', id)
    .single();
  if (error) return null;
  return data;
}

async function notify(adminId, taskId, type, message) {
  const { error } = await supabase.from('task_notifications').insert({ admin_id: adminId, task_id: taskId, type, message });
  if (error) {
    logger.error('[tasks] in-app notification insert failed', { adminId, taskId, type, error: error.message });
    return { sent: false, reason: 'db_error' };
  }
  return { sent: true };
}

// task_assignees has TWO foreign keys to superadmin_credentials (admin_id and
// assigned_by). A bare `superadmin_credentials(...)` embed is ambiguous and
// PostgREST rejects the whole query (PGRST201) — which previously came back
// as "no assignees", so assignees got 403 on their own tasks. Always name
// the FK explicitly.
export const ASSIGNEE_EMBED = 'superadmin_credentials!task_assignees_admin_id_fkey(id, email, username, full_name)';

const mapAssignee = (a) => ({
  id: a.superadmin_credentials?.id,
  email: a.superadmin_credentials?.email,
  username: a.superadmin_credentials?.username,
  fullName: a.superadmin_credentials?.full_name,
  assignedAt: a.assigned_at,
});

async function getTaskWithChildren(taskId) {
  const { data: task, error } = await supabase.from('tasks').select('*').eq('id', taskId).maybeSingle();
  if (error) throw error;
  if (!task) return null;

  const [stagesRes, assigneesRes] = await Promise.all([
    supabase.from('task_stages').select('*').eq('task_id', taskId).order('order_index', { ascending: true }),
    supabase.from('task_assignees').select(`admin_id, assigned_at, ${ASSIGNEE_EMBED}`).eq('task_id', taskId),
  ]);
  if (stagesRes.error) throw stagesRes.error;
  if (assigneesRes.error) throw assigneesRes.error;

  return {
    ...task,
    stages: stagesRes.data || [],
    assignees: (assigneesRes.data || []).map(mapAssignee),
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Normalise a phone number to E.164. Accepts Kenyan local formats
// (07xx…, 01xx…, 7xx…, 2547xx…) as a convenience. Returns null if invalid.
export function normalisePhone(input) {
  let n = String(input || '').replace(/[\s\-().]/g, '');
  if (!n) return null;
  if (n.startsWith('00')) n = `+${n.slice(2)}`;
  if (/^0[17]\d{8}$/.test(n)) n = `+254${n.slice(1)}`;
  else if (/^[17]\d{8}$/.test(n)) n = `+254${n}`;
  else if (!n.startsWith('+')) n = `+${n}`;
  return /^\+[1-9]\d{7,14}$/.test(n) ? n : null;
}

// Load active admins by id, including phone (server-side only — phone
// numbers are never sent to other admins' browsers).
async function loadActiveAdmins(ids) {
  const { data, error } = await supabase
    .from('superadmin_credentials')
    .select('id, email, username, full_name, phone_number, status')
    .in('id', ids);
  if (error) throw error;
  return (data || []).filter(a => a.status === 'active');
}

/**
 * Deliver an "assigned" notice on every channel and report per-channel status.
 * In-app is the source of truth; email + WhatsApp are best-effort and never
 * throw, but their outcome is returned so the manager sees what happened.
 */
async function deliverAssignment(task, admin, assignedByName, inAppMessage) {
  const name = admin.full_name || admin.username;
  const { subject, html } = taskEmailTemplates.assigned(task, name, assignedByName);
  const [inApp, email, whatsapp] = await Promise.all([
    notify(admin.id, task.id, 'assigned', inAppMessage || `New task assigned: "${task.title}"`),
    sendTaskEmail(admin.email, subject, html),
    admin.phone_number
      ? sendTaskAssignedWhatsApp(admin.phone_number, name, task.title).catch(err => ({ sent: false, reason: err.message }))
      : Promise.resolve({ sent: false, reason: 'no_phone' }),
  ]);
  const result = { adminId: admin.id, name, inApp, email, whatsapp };
  logger.info('[tasks] assignment delivery', {
    taskId: task.id, adminId: admin.id,
    inApp: inApp.sent, email: email.sent || email.reason, whatsapp: whatsapp.sent || whatsapp.reason,
  });
  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// GET /context — current admin's task role + roster (for the assignee
// picker). Cheap, called once when the Tasks tab mounts.
// ═══════════════════════════════════════════════════════════════════════
router.get('/context', authenticateSuperadmin, async (req, res) => {
  try {
    const { data: admins, error } = await supabase
      .from('superadmin_credentials')
      .select('id, email, username, full_name, task_role, phone_number')
      .eq('status', 'active')
      .order('username', { ascending: true });
    if (error) throw error;

    ok(res, {
      me: {
        id: req.superadmin.id,
        email: req.superadmin.email,
        username: req.superadmin.username,
        full_name: req.superadmin.full_name,
        task_role: req.superadmin.task_role,
        phone_number: req.superadmin.phone_number || null, // own number only
      },
      // Other admins' phone numbers stay server-side; the UI only needs to
      // know whether WhatsApp delivery is possible.
      admins: (admins || []).map(({ phone_number, ...a }) => ({ ...a, has_whatsapp: !!phone_number })),
    });
  } catch (e) {
    logger.error('[tasks] context failed', { error: e.message });
    bad(res, 500, 'Failed to load task context');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// PUT /me/phone — an admin sets (or clears) their own WhatsApp number for
// task notifications. Self-service only: nobody can change someone else's.
// ═══════════════════════════════════════════════════════════════════════
router.put('/me/phone', authenticateSuperadmin, async (req, res) => {
  try {
    const raw = req.body?.phone;
    let phone = null;
    if (raw !== null && raw !== undefined && String(raw).trim() !== '') {
      phone = normalisePhone(raw);
      if (!phone) return bad(res, 422, 'Enter a valid phone number in international format, e.g. +254712345678');
    }
    const { error } = await supabase
      .from('superadmin_credentials')
      .update({ phone_number: phone })
      .eq('id', req.superadmin.id);
    if (error) throw error;

    await logTaskAudit(req.superadmin.id, 'TASK_PHONE_UPDATED', req.superadmin.id, phone ? 'set' : 'cleared', req);
    ok(res, { phone_number: phone }, phone ? 'WhatsApp number saved' : 'WhatsApp number removed');
  } catch (e) {
    logger.error('[tasks] phone update failed', { error: e.message });
    bad(res, 500, 'Could not save phone number');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GET / — list tasks. Task managers see everything; members see only
// tasks assigned to them.
// ═══════════════════════════════════════════════════════════════════════
router.get('/', authenticateSuperadmin, async (req, res) => {
  try {
    let taskIds = null;
    if (req.superadmin.task_role !== 'task_manager') {
      const { data: rows, error: rowsErr } = await supabase
        .from('task_assignees')
        .select('task_id')
        .eq('admin_id', req.superadmin.id);
      if (rowsErr) throw rowsErr;
      taskIds = (rows || []).map(r => r.task_id);
      if (taskIds.length === 0) return ok(res, []);
    }

    let query = supabase.from('tasks').select('*').order('deadline', { ascending: true });
    if (taskIds) query = query.in('id', taskIds);
    const { data: tasks, error } = await query;
    if (error) throw error;
    if (!tasks?.length) return ok(res, []);

    // Only fetch children of the tasks we're returning.
    const ids = tasks.map(t => t.id);
    const [stagesRes, assigneesRes] = await Promise.all([
      supabase.from('task_stages').select('*').in('task_id', ids).order('order_index', { ascending: true }),
      supabase.from('task_assignees').select(`task_id, admin_id, assigned_at, ${ASSIGNEE_EMBED}`).in('task_id', ids),
    ]);
    if (stagesRes.error) throw stagesRes.error;
    if (assigneesRes.error) throw assigneesRes.error;

    const stagesByTask = {};
    (stagesRes.data || []).forEach(s => { (stagesByTask[s.task_id] ||= []).push(s); });
    const assigneesByTask = {};
    (assigneesRes.data || []).forEach(a => { (assigneesByTask[a.task_id] ||= []).push(mapAssignee(a)); });

    ok(res, tasks.map(t => ({
      ...t,
      stages: stagesByTask[t.id] || [],
      assignees: assigneesByTask[t.id] || [],
    })));
  } catch (e) {
    logger.error('[tasks] list failed', { error: e.message });
    bad(res, 500, 'Failed to load tasks');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /:id — single task detail
// ═══════════════════════════════════════════════════════════════════════
router.get('/:id', authenticateSuperadmin, async (req, res) => {
  try {
    if (!UUID_RE.test(req.params.id)) return bad(res, 404, 'Task not found');
    const task = await getTaskWithChildren(req.params.id);
    if (!task) return bad(res, 404, 'Task not found');

    if (req.superadmin.task_role !== 'task_manager') {
      const isAssignee = task.assignees.some(a => a.id === req.superadmin.id);
      if (!isAssignee) return bad(res, 403, 'Not assigned to this task');
    }
    ok(res, task);
  } catch (e) {
    logger.error('[tasks] get failed', { taskId: req.params.id, error: e.message });
    bad(res, 500, 'Failed to load task');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// POST / — create a task with stages + assignees (task manager only)
// body: { title, description, deadline, reminderOffsetsHours, stages: [{title, description, weightPercent}], assigneeIds: [] }
// ═══════════════════════════════════════════════════════════════════════
router.post('/', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  let createdTaskId = null;
  try {
    const { title, description, deadline, reminderOffsetsHours, stages, assigneeIds } = req.body || {};

    // ── validation ──────────────────────────────────────────────────────
    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    if (!cleanTitle) return bad(res, 400, 'Title is required');
    if (cleanTitle.length > 200) return bad(res, 400, 'Title must be 200 characters or fewer');
    if (description != null && typeof description !== 'string') return bad(res, 400, 'Invalid description');
    if ((description || '').length > 5000) return bad(res, 400, 'Description must be 5000 characters or fewer');

    const deadlineDate = new Date(deadline);
    if (!deadline || isNaN(deadlineDate.getTime())) return bad(res, 400, 'A valid deadline is required');
    if (deadlineDate.getTime() <= Date.now()) return bad(res, 400, 'Deadline must be in the future');

    if (!Array.isArray(stages) || stages.length === 0) return bad(res, 400, 'At least one stage is required');
    if (stages.length > 30) return bad(res, 400, 'A task can have at most 30 stages');
    for (const s of stages) {
      const t = typeof s?.title === 'string' ? s.title.trim() : '';
      const w = Number(s?.weightPercent);
      if (!t || t.length > 200) return bad(res, 400, 'Every stage needs a title (max 200 characters)');
      if (!Number.isFinite(w) || w <= 0 || w > 100) return bad(res, 400, `Stage "${t}" needs a weight between 0 and 100`);
    }
    const weightSum = stages.reduce((sum, s) => sum + Number(s.weightPercent), 0);
    if (Math.abs(weightSum - 100) > 0.01) {
      return bad(res, 400, `Stage weights must add up to 100% (currently ${Math.round(weightSum * 100) / 100}%)`);
    }

    if (!Array.isArray(assigneeIds) || assigneeIds.length === 0) return bad(res, 400, 'At least one assignee is required');
    const uniqueAssignees = [...new Set(assigneeIds.map(String))];
    if (uniqueAssignees.length > 50 || uniqueAssignees.some(id => !UUID_RE.test(id))) {
      return bad(res, 400, 'Invalid assignee list');
    }
    // Only real, active superadmins can be assigned — never trust raw ids.
    const assigneeAdmins = await loadActiveAdmins(uniqueAssignees);
    if (assigneeAdmins.length !== uniqueAssignees.length) {
      return bad(res, 400, 'One or more selected assignees no longer exist or are not active. Refresh and try again.');
    }

    const offsets = Array.isArray(reminderOffsetsHours)
      ? [...new Set(reminderOffsetsHours.map(Number).filter(h => Number.isInteger(h) && h > 0 && h <= 24 * 60))]
      : [];

    // ── writes (rolled back on any failure so no half-created tasks) ─────
    const { data: task, error: taskErr } = await supabase
      .from('tasks')
      .insert({
        title: cleanTitle,
        description: description?.trim() || null,
        deadline: deadlineDate.toISOString(),
        reminder_offsets_hours: offsets.length ? offsets.sort((a, b) => b - a) : [72, 24, 3],
        created_by: req.superadmin.id,
      })
      .select()
      .single();
    if (taskErr) throw taskErr;
    createdTaskId = task.id;

    const { error: stageErr } = await supabase.from('task_stages').insert(stages.map((s, i) => ({
      task_id: task.id,
      title: s.title.trim(),
      description: typeof s.description === 'string' && s.description.trim() ? s.description.trim().slice(0, 2000) : null,
      weight_percent: Number(s.weightPercent),
      order_index: i,
    })));
    if (stageErr) throw stageErr;

    const { error: assignErr } = await supabase.from('task_assignees').insert(uniqueAssignees.map(adminId => ({
      task_id: task.id,
      admin_id: adminId,
      assigned_by: req.superadmin.id,
    })));
    if (assignErr) throw assignErr;

    createdTaskId = null; // committed — nothing to roll back from here on

    // ── notify every assignee on every channel; collect a delivery report ─
    const assignedByName = req.superadmin.full_name || req.superadmin.username;
    const delivery = await Promise.all(assigneeAdmins.map(a => deliverAssignment(task, a, assignedByName)));

    await logTaskAudit(req.superadmin.id, 'TASK_CREATED', task.id, `"${task.title}" — ${uniqueAssignees.length} assignee(s)`, req);

    const full = await getTaskWithChildren(task.id);
    res.status(201).json({ success: true, data: full, delivery, message: 'Task created' });
  } catch (e) {
    logger.error('[tasks] create failed', { error: e.message, code: e.code, details: e.details });
    if (createdTaskId) {
      // Best-effort rollback of partial writes.
      await supabase.from('task_assignees').delete().eq('task_id', createdTaskId);
      await supabase.from('task_stages').delete().eq('task_id', createdTaskId);
      const { error: rbErr } = await supabase.from('tasks').delete().eq('id', createdTaskId);
      if (rbErr) logger.error('[tasks] rollback failed', { taskId: createdTaskId, error: rbErr.message });
    }
    bad(res, 500, 'Could not create the task. Nothing was saved — please try again.');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// PUT /:id — edit title/description/deadline/reminder offsets (task manager only)
// ═══════════════════════════════════════════════════════════════════════
router.put('/:id', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const { title, description, deadline, reminderOffsetsHours } = req.body;
    const patch = { updated_at: new Date().toISOString() };
    if (title !== undefined) patch.title = title.trim();
    if (description !== undefined) patch.description = description?.trim() || null;
    if (deadline !== undefined) {
      if (isNaN(new Date(deadline).getTime())) return bad(res, 400, 'Invalid deadline');
      patch.deadline = deadline;
    }
    if (Array.isArray(reminderOffsetsHours)) patch.reminder_offsets_hours = reminderOffsetsHours;

    const { error } = await supabase.from('tasks').update(patch).eq('id', req.params.id);
    if (error) throw error;

    await logTaskAudit(req.superadmin.id, 'TASK_UPDATED', req.params.id, '', req);

    const full = await getTaskWithChildren(req.params.id);
    ok(res, full, 'Task updated');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to update task');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// DELETE /:id — cancel a task (task manager only). Soft-cancel, not a hard
// delete, so history/audit stays intact.
// ═══════════════════════════════════════════════════════════════════════
router.delete('/:id', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const { error } = await supabase
      .from('tasks')
      .update({ status: 'cancelled', cancelled_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;

    const task = await getTaskWithChildren(req.params.id);
    await Promise.all((task?.assignees || []).map(a =>
      notify(a.id, task.id, 'task_cancelled', `Task cancelled: "${task.title}"`)
    ));

    await logTaskAudit(req.superadmin.id, 'TASK_CANCELLED', req.params.id, `"${task?.title || ''}"`, req);

    ok(res, null, 'Task cancelled');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to cancel task');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// POST /:id/assignees — add an assignee (task manager only)
// ═══════════════════════════════════════════════════════════════════════
router.post('/:id/assignees', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const adminId = String(req.body?.adminId || '');
    if (!UUID_RE.test(adminId)) return bad(res, 400, 'A valid adminId is required');
    if (!UUID_RE.test(req.params.id)) return bad(res, 404, 'Task not found');

    const existing = await getTaskWithChildren(req.params.id);
    if (!existing) return bad(res, 404, 'Task not found');
    if (existing.status !== 'active') return bad(res, 400, 'Only active tasks can be reassigned');

    const [admin] = await loadActiveAdmins([adminId]);
    if (!admin) return bad(res, 400, 'That admin does not exist or is not active');

    const { error } = await supabase
      .from('task_assignees')
      .insert({ task_id: existing.id, admin_id: admin.id, assigned_by: req.superadmin.id });
    const alreadyAssigned = error?.code === '23505';
    if (error && !alreadyAssigned) throw error;

    // Only notify on a genuinely new assignment — no duplicate pings.
    let delivery = [];
    if (!alreadyAssigned) {
      delivery = [await deliverAssignment(existing, admin, req.superadmin.full_name || req.superadmin.username,
        `You were added to task: "${existing.title}"`)];
      await logTaskAudit(req.superadmin.id, 'TASK_ASSIGNEE_ADDED', existing.id, admin.email, req);
    }

    const task = await getTaskWithChildren(existing.id);
    res.json({ success: true, data: task, delivery, message: alreadyAssigned ? 'Already assigned' : 'Assignee added' });
  } catch (e) {
    logger.error('[tasks] add assignee failed', { taskId: req.params.id, error: e.message });
    bad(res, 500, 'Failed to add assignee');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// DELETE /:id/assignees/:adminId — remove an assignee (task manager only)
// ═══════════════════════════════════════════════════════════════════════
router.delete('/:id/assignees/:adminId', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const { error } = await supabase
      .from('task_assignees')
      .delete()
      .eq('task_id', req.params.id)
      .eq('admin_id', req.params.adminId);
    if (error) throw error;

    await logTaskAudit(req.superadmin.id, 'TASK_ASSIGNEE_REMOVED', req.params.id, req.params.adminId, req);

    const task = await getTaskWithChildren(req.params.id);
    ok(res, task, 'Assignee removed');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to remove assignee');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// POST /:taskId/stages/:stageId/complete — mark a stage done.
// Any assignee of the task, or the task manager, can do this.
// ═══════════════════════════════════════════════════════════════════════
router.post('/:taskId/stages/:stageId/complete', authenticateSuperadmin, async (req, res) => {
  try {
    const { taskId, stageId } = req.params;
    const before = await getTaskWithChildren(taskId);
    if (!before) return bad(res, 404, 'Task not found');

    const isAssignee = before.assignees.some(a => a.id === req.superadmin.id);
    if (req.superadmin.task_role !== 'task_manager' && !isAssignee) {
      return bad(res, 403, 'Not assigned to this task');
    }
    if (before.status !== 'active') return bad(res, 400, 'Task is not active');

    const stage = before.stages.find(s => s.id === stageId);
    if (!stage) return bad(res, 404, 'Stage not found');
    if (stage.status === 'completed') return bad(res, 400, 'Stage already completed');

    const { error } = await supabase
      .from('task_stages')
      .update({
        status: 'completed',
        completed_by: req.superadmin.id,
        completed_at: new Date().toISOString(),
        notes: req.body?.notes?.trim() || null,
      })
      .eq('id', stageId);
    if (error) throw error;

    const after = await getTaskWithChildren(taskId);
    const actorName = req.superadmin.full_name || req.superadmin.username;
    const completedStage = after.stages.find(s => s.id === stageId);

    // Notify the rest of the task's people (assignees minus the actor + the creator).
    const recipients = new Map();
    after.assignees.forEach(a => { if (a.id !== req.superadmin.id) recipients.set(a.id, a); });
    if (before.created_by !== req.superadmin.id) {
      const creator = await getAdmin(before.created_by);
      if (creator) recipients.set(creator.id, creator);
    }
    await Promise.all([...recipients.values()].map(async (r) => {
      await notify(r.id, taskId, 'stage_completed', `${actorName} completed "${stage.title}" on "${after.title}" (${after.progress_percent}%)`);
      const { subject, html } = taskEmailTemplates.stageCompleted(after, completedStage, actorName);
      await sendTaskEmail(r.email, subject, html);
    }));

    // Task just crossed 100% — send a single completion notice.
    if (before.status === 'active' && after.status === 'completed') {
      const everyone = new Map(recipients);
      everyone.set(req.superadmin.id, { id: req.superadmin.id, email: req.superadmin.email });
      await Promise.all([...everyone.values()].map(async (r) => {
        await notify(r.id, taskId, 'task_completed', `Task completed: "${after.title}"`);
        const { subject, html } = taskEmailTemplates.taskCompleted(after);
        await sendTaskEmail(r.email, subject, html);
      }));
    }

    await logTaskAudit(req.superadmin.id, 'TASK_STAGE_COMPLETED', taskId, stage.title, req);

    ok(res, after, 'Stage marked complete');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to complete stage');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// POST /:taskId/stages/:stageId/reopen — undo a completed stage (task manager only)
// ═══════════════════════════════════════════════════════════════════════
router.post('/:taskId/stages/:stageId/reopen', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const { taskId, stageId } = req.params;
    const { error } = await supabase
      .from('task_stages')
      .update({ status: 'pending', completed_by: null, completed_at: null })
      .eq('id', stageId)
      .eq('task_id', taskId);
    if (error) throw error;

    // If the task had auto-completed, reopen it too.
    await supabase
      .from('tasks')
      .update({ status: 'active', completed_at: null, updated_at: new Date().toISOString() })
      .eq('id', taskId)
      .eq('status', 'completed');

    await logTaskAudit(req.superadmin.id, 'TASK_STAGE_REOPENED', taskId, stageId, req);

    const task = await getTaskWithChildren(taskId);
    ok(res, task, 'Stage reopened');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to reopen stage');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Notifications
// ═══════════════════════════════════════════════════════════════════════
router.get('/notifications/list', authenticateSuperadmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 30, 100);
    const { data, error } = await supabase
      .from('task_notifications')
      .select('*')
      .eq('admin_id', req.superadmin.id)
      .order('created_at', { ascending: false })
      .limit(limit);
    if (error) throw error;

    const { count } = await supabase
      .from('task_notifications')
      .select('id', { count: 'exact', head: true })
      .eq('admin_id', req.superadmin.id)
      .eq('is_read', false);

    ok(res, { notifications: data || [], unreadCount: count || 0 });
  } catch (e) {
    bad(res, 500, e.message || 'Failed to load notifications');
  }
});

router.post('/notifications/:id/read', authenticateSuperadmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('task_notifications')
      .update({ is_read: true })
      .eq('id', req.params.id)
      .eq('admin_id', req.superadmin.id);
    if (error) throw error;
    ok(res, null);
  } catch (e) {
    bad(res, 500, e.message || 'Failed to mark as read');
  }
});

router.post('/notifications/read-all', authenticateSuperadmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('task_notifications')
      .update({ is_read: true })
      .eq('admin_id', req.superadmin.id)
      .eq('is_read', false);
    if (error) throw error;
    ok(res, null);
  } catch (e) {
    bad(res, 500, e.message || 'Failed to mark all as read');
  }
});

export default router;