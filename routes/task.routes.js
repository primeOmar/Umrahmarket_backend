import express from 'express';
import { supabaseAdmin as supabase } from '../config/supabase.js';
import { authenticateSuperadmin } from './superadmin_routes.js';
import { sendTaskEmail, taskEmailTemplates } from '../services/taskEmail.service.js';

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
  await supabase.from('task_notifications').insert({ admin_id: adminId, task_id: taskId, type, message });
}

async function getTaskWithChildren(taskId) {
  const { data: task, error } = await supabase.from('tasks').select('*').eq('id', taskId).single();
  if (error || !task) return null;

  const [{ data: stages }, { data: assignees }] = await Promise.all([
    supabase.from('task_stages').select('*').eq('task_id', taskId).order('order_index', { ascending: true }),
    supabase
      .from('task_assignees')
      .select('admin_id, assigned_at, superadmin_credentials(id, email, username, full_name)')
      .eq('task_id', taskId),
  ]);

  return {
    ...task,
    stages: stages || [],
    assignees: (assignees || []).map(a => ({
      id: a.superadmin_credentials?.id,
      email: a.superadmin_credentials?.email,
      username: a.superadmin_credentials?.username,
      fullName: a.superadmin_credentials?.full_name,
      assignedAt: a.assigned_at,
    })),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// GET /context — current admin's task role + roster (for the assignee
// picker). Cheap, called once when the Tasks tab mounts.
// ═══════════════════════════════════════════════════════════════════════
router.get('/context', authenticateSuperadmin, async (req, res) => {
  const { data: admins } = await supabase
    .from('superadmin_credentials')
    .select('id, email, username, full_name, task_role')
    .eq('status', 'active')
    .order('username', { ascending: true });

  ok(res, {
    me: {
      id: req.superadmin.id,
      email: req.superadmin.email,
      username: req.superadmin.username,
      full_name: req.superadmin.full_name,
      task_role: req.superadmin.task_role,
    },
    admins: admins || [],
  });
});

// ═══════════════════════════════════════════════════════════════════════
// GET / — list tasks. Task managers see everything; members see only
// tasks assigned to them.
// ═══════════════════════════════════════════════════════════════════════
router.get('/', authenticateSuperadmin, async (req, res) => {
  try {
    let taskIds = null;
    if (req.superadmin.task_role !== 'task_manager') {
      const { data: rows } = await supabase
        .from('task_assignees')
        .select('task_id')
        .eq('admin_id', req.superadmin.id);
      taskIds = (rows || []).map(r => r.task_id);
      if (taskIds.length === 0) return ok(res, []);
    }

    let query = supabase.from('tasks').select('*').order('deadline', { ascending: true });
    if (taskIds) query = query.in('id', taskIds);
    const { data: tasks, error } = await query;
    if (error) throw error;

    const [{ data: stages }, { data: assignees }] = await Promise.all([
      supabase.from('task_stages').select('*').order('order_index', { ascending: true }),
      supabase.from('task_assignees').select('task_id, admin_id, superadmin_credentials(id, email, username, full_name)'),
    ]);

    const stagesByTask = {};
    (stages || []).forEach(s => { (stagesByTask[s.task_id] ||= []).push(s); });
    const assigneesByTask = {};
    (assignees || []).forEach(a => {
      (assigneesByTask[a.task_id] ||= []).push({
        id: a.superadmin_credentials?.id,
        email: a.superadmin_credentials?.email,
        username: a.superadmin_credentials?.username,
        fullName: a.superadmin_credentials?.full_name,
      });
    });

    const result = (tasks || [])
      .filter(t => !taskIds || taskIds.includes(t.id))
      .map(t => ({
        ...t,
        stages: stagesByTask[t.id] || [],
        assignees: assigneesByTask[t.id] || [],
      }));

    ok(res, result);
  } catch (e) {
    bad(res, 500, e.message || 'Failed to load tasks');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GET /:id — single task detail
// ═══════════════════════════════════════════════════════════════════════
router.get('/:id', authenticateSuperadmin, async (req, res) => {
  const task = await getTaskWithChildren(req.params.id);
  if (!task) return bad(res, 404, 'Task not found');

  if (req.superadmin.task_role !== 'task_manager') {
    const isAssignee = task.assignees.some(a => a.id === req.superadmin.id);
    if (!isAssignee) return bad(res, 403, 'Not assigned to this task');
  }
  ok(res, task);
});

// ═══════════════════════════════════════════════════════════════════════
// POST / — create a task with stages + assignees (task manager only)
// body: { title, description, deadline, reminderOffsetsHours, stages: [{title, description, weightPercent}], assigneeIds: [] }
// ═══════════════════════════════════════════════════════════════════════
router.post('/', authenticateSuperadmin, requireTaskManager, async (req, res) => {
  try {
    const { title, description, deadline, reminderOffsetsHours, stages, assigneeIds } = req.body;

    if (!title?.trim()) return bad(res, 400, 'Title is required');
    if (!deadline || isNaN(new Date(deadline).getTime())) return bad(res, 400, 'A valid deadline is required');
    if (new Date(deadline).getTime() <= Date.now()) return bad(res, 400, 'Deadline must be in the future');
    if (!Array.isArray(stages) || stages.length === 0) return bad(res, 400, 'At least one stage is required');
    if (!Array.isArray(assigneeIds) || assigneeIds.length === 0) return bad(res, 400, 'At least one assignee is required');

    const weightSum = stages.reduce((sum, s) => sum + Number(s.weightPercent || 0), 0);
    if (Math.abs(weightSum - 100) > 0.01) {
      return bad(res, 400, `Stage weights must add up to 100% (currently ${weightSum}%)`);
    }

    const { data: task, error: taskErr } = await supabase
      .from('tasks')
      .insert({
        title: title.trim(),
        description: description?.trim() || null,
        deadline,
        reminder_offsets_hours: Array.isArray(reminderOffsetsHours) && reminderOffsetsHours.length
          ? reminderOffsetsHours
          : [72, 24, 3],
        created_by: req.superadmin.id,
      })
      .select()
      .single();
    if (taskErr) throw taskErr;

    const stageRows = stages.map((s, i) => ({
      task_id: task.id,
      title: s.title.trim(),
      description: s.description?.trim() || null,
      weight_percent: Number(s.weightPercent),
      order_index: i,
    }));
    const { error: stageErr } = await supabase.from('task_stages').insert(stageRows);
    if (stageErr) throw stageErr;

    const uniqueAssignees = [...new Set(assigneeIds)];
    const assigneeRows = uniqueAssignees.map(adminId => ({
      task_id: task.id,
      admin_id: adminId,
      assigned_by: req.superadmin.id,
    }));
    const { error: assignErr } = await supabase.from('task_assignees').insert(assigneeRows);
    if (assignErr) throw assignErr;

    const { data: assigneeAdmins } = await supabase
      .from('superadmin_credentials')
      .select('id, email, username, full_name')
      .in('id', uniqueAssignees);

    await Promise.all((assigneeAdmins || []).map(async (a) => {
      await notify(a.id, task.id, 'assigned', `New task assigned: "${task.title}"`);
      const { subject, html } = taskEmailTemplates.assigned(task, a.full_name || a.username);
      await sendTaskEmail(a.email, subject, html);
    }));

    await logTaskAudit(req.superadmin.id, 'TASK_CREATED', task.id, `"${task.title}" — ${uniqueAssignees.length} assignee(s)`, req);

    const full = await getTaskWithChildren(task.id);
    ok(res, full, 'Task created');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to create task');
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
    const { adminId } = req.body;
    if (!adminId) return bad(res, 400, 'adminId is required');

    const { error } = await supabase
      .from('task_assignees')
      .insert({ task_id: req.params.id, admin_id: adminId, assigned_by: req.superadmin.id });
    if (error && error.code !== '23505') throw error; // ignore duplicate

    const task = await getTaskWithChildren(req.params.id);
    const admin = await getAdmin(adminId);
    if (admin) {
      await notify(admin.id, task.id, 'assigned', `You were added to task: "${task.title}"`);
      const { subject, html } = taskEmailTemplates.assigned(task, admin.full_name || admin.username);
      await sendTaskEmail(admin.email, subject, html);
    }

    await logTaskAudit(req.superadmin.id, 'TASK_ASSIGNEE_ADDED', req.params.id, admin?.email || adminId, req);

    ok(res, task, 'Assignee added');
  } catch (e) {
    bad(res, 500, e.message || 'Failed to add assignee');
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