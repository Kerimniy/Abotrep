use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct HumanCheckRequest {
    pub timediff: u32,

    pub scroll_times: Vec<f64>,
    pub pointer_points: Vec<PointerPoint>,
    pub hovers_count: u32,
    pub is_touch: bool,
}

#[derive(Deserialize, Debug)]
pub struct PointerPoint {
    pub x: f64,
    pub y: f64,
    pub t: f64,
}

//
// ===== JS-equivalent helper functions =====
//

fn velocity_variation(times: &[f64]) -> f64 {
    if times.len() < 3 { return 0.0; }

    let mut diffs = Vec::new();
    for i in 1..times.len() {
        diffs.push(times[i] - times[i - 1]);
    }

    let avg = diffs.iter().sum::<f64>() / diffs.len() as f64;
    if avg == 0.0 { return 0.0; }

    let varsum: f64 = diffs.iter().map(|d| (d - avg) * (d - avg)).sum();
    let std = (varsum / diffs.len() as f64).sqrt();

    std / avg
}

fn has_random_pauses(times: &[f64]) -> bool {
    if times.len() < 2 { return false; }
    for i in 1..times.len() {
        if times[i] - times[i - 1] > 70.0 {
            return true;
        }
    }
    false
}

fn detect_touch_stop(points: &[PointerPoint]) -> bool {
    if points.len() < 4 { return false; }

    let n = points.len();

    let v_last = ((points[n - 1].x - points[n - 2].x).powi(2)
        + (points[n - 1].y - points[n - 2].y).powi(2))
        .sqrt();

    let v_prev = ((points[n - 2].x - points[n - 3].x).powi(2)
        + (points[n - 2].y - points[n - 3].y).powi(2))
        .sqrt();

    v_prev > v_last
}

fn detect_micro_jitter(points: &[PointerPoint]) -> u32 {
    if points.len() < 6 { return 0; } // JS: requires >= 6

    let mut jitter = 0;
    for i in 1..points.len() {
        let dx = (points[i].x - points[i - 1].x).abs();
        let dy = (points[i].y - points[i - 1].y).abs();
        if dx < 2.0 && dy < 2.0 {
            jitter += 1;
        }
    }
    jitter
}

fn check_points(points: &[PointerPoint]) -> bool {
    if points.len() < 6 {
        return false;
    }

    let mut last_x = None::<i32>;
    let mut last_y = None::<i32>;
    let mut cd = 0; // direction changes
    let mut max_speed = 0.0;

    for i in 1..points.len() {
        let dx = points[i].x - points[i - 1].x;
        let dy = points[i].y - points[i - 1].y;
        let mut dt = points[i].t - points[i - 1].t;
        if dt <= 0.0 { dt = 0.001; }

        let speed = ((dx / dt).powi(2) + (dy / dt).powi(2)).sqrt();
        if speed > max_speed { max_speed = speed; }

        if dx != 0.0 {
            let dir = if dx > 0.0 { 1 } else { -1 };
            if let Some(l) = last_x {
                if dir != l {
                    cd += 1;
                }
            }
            last_x = Some(dir);
        }

        if dy != 0.0 {
            let dir = if dy > 0.0 { 1 } else { -1 };
            if let Some(l) = last_y {
                if dir != l {
                    cd += 1;
                }
            }
            last_y = Some(dir);
        }
    }

    cd >= 3 && max_speed < 100.0
}

fn analyze_jerk(times: &[f64]) -> f64 {
    if times.len() < 4 { return 0.0; }

    let mut diffs = Vec::new();
    for i in 1..times.len() {
        diffs.push(times[i] - times[i - 1]);
    }

    let mut jerk = Vec::new();
    for i in 1..diffs.len() {
        jerk.push((diffs[i] - diffs[i - 1]).abs());
    }

    if jerk.is_empty() { return 0.0; }

    jerk.sort_by(|a, b| a.partial_cmp(b).unwrap());
    jerk[jerk.len() / 2]
}

//
// ===== Touch human check (JS clone) =====
//

fn is_human_touch_js(req: &HumanCheckRequest) -> bool {


    let score =
        velocity_variation(&req.scroll_times)
            + has_random_pauses(&req.scroll_times) as u8 as f64
            + detect_touch_stop(&req.pointer_points) as u8 as f64;

    score > 1.0
}


fn is_human_mouse_js(req: &HumanCheckRequest) -> bool {



    let jitter = detect_micro_jitter(&req.pointer_points);
    let dirs_ok = check_points(&req.pointer_points);

    if !dirs_ok && jitter < 2 {
        return false;
    }

    let jerk_scroll = analyze_jerk(&req.scroll_times);

    let pointer_times: Vec<f64> =
        req.pointer_points.iter().map(|p| p.t).collect();
    let jerk_pointer = analyze_jerk(&pointer_times);

    if jerk_scroll < 0.1 && jerk_pointer < 0.1 {
        return false;
    }

    if req.timediff < 2 {
        return false;
    }

    if req.hovers_count < 2 {
        return false;
    }

    true
}

pub fn is_human(req: HumanCheckRequest) -> bool {
    if req.is_touch {
        is_human_touch_js(&req)
    } else {
        is_human_mouse_js(&req)
    }
}
