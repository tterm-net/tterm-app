//! Notes on this computer (from 0.2.0), through the page's requests: the
//! cases of tterm-web's `tterm/tests/test_notes.py` that are not about other
//! people and their roles, with the same names and words.

mod common;

use common::{engine, request};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tterm_engine::{api, notes, Engine};

fn p(id: &str, text: &str) -> Value {
    json!({"id": id, "type": "p", "text": text})
}

fn todo(id: &str, text: &str, done: bool) -> Value {
    json!({"id": id, "type": "todo", "text": text, "done": done})
}

/// An engine whose person is named, and the id of Personal.
async fn named() -> (Arc<Engine>, String) {
    let e = engine().await;
    let (status, _) = request(&e, "PATCH", "/api/me", json!({"name": "Denis Gerasimenko"})).await;
    assert_eq!(status, 200);
    let pid = e.settings.lock().unwrap().project_id.to_string();
    (e, pid)
}

async fn folder(e: &Arc<Engine>, pid: &str, name: &str) -> Value {
    let (status, f) = request(e, "POST", "/api/folders", json!({"projectId": pid, "name": name})).await;
    assert_eq!(status, 201, "{f}");
    f
}

async fn note(e: &Arc<Engine>, folder_id: &str, title: &str) -> Value {
    let (status, n) = request(e, "POST", "/api/notes", json!({"folderId": folder_id, "title": title})).await;
    assert_eq!(status, 201, "{n}");
    n
}

async fn save(e: &Arc<Engine>, id: &str, base: i64, title: &str, blocks: Value) -> (u16, Value) {
    request(e, "PUT", &format!("/api/notes/{id}"), json!({"baseVersion": base, "title": title, "blocks": blocks})).await
}

async fn listed(e: &Arc<Engine>) -> Vec<Value> {
    let (_, state) = request(e, "GET", "/api/state", Value::Null).await;
    state["projects"][0]["folders"].as_array().unwrap().clone()
}

async fn count(e: &Arc<Engine>, table: &'static str) -> i64 {
    e.terminals.store.run(move |c| c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap()).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn folders_made_renamed_deleted() {
    let (e, pid) = named().await;
    let runbooks = folder(&e, &pid, " Runbooks ").await;
    assert_eq!(runbooks["name"], "Runbooks");
    assert_eq!(runbooks["createdBy"]["initials"], "DG");
    assert_eq!(runbooks["notes"], json!([]));
    for name in ["runbooks", "RUNBOOKS "] {
        let (status, refused) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": name})).await;
        assert_eq!(status, 409, "a second folder named {name:?}");
        assert!(refused["error"].as_str().unwrap().to_lowercase().contains("runbooks"), "{refused}");
    }
    // Case, as the core's database lowers it: not only in ASCII.
    folder(&e, &pid, "Заметки").await;
    let (status, _) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": "ЗАМЕТКИ"})).await;
    assert_eq!(status, 409);
    let team = folder(&e, &pid, "Team").await;
    let tid = team["id"].as_str().unwrap();
    let (status, renamed) = request(&e, "PATCH", &format!("/api/folders/{tid}"), json!({"name": "People and access"})).await;
    assert_eq!((status, renamed["name"].as_str()), (200, Some("People and access")));
    // Its own name in another case is fine.
    let (status, _) = request(&e, "PATCH", &format!("/api/folders/{tid}"), json!({"name": "people and access"})).await;
    assert_eq!(status, 200);
    let (status, _) = request(&e, "PATCH", &format!("/api/folders/{tid}"), json!({"name": "RUNBOOKS"})).await;
    assert_eq!(status, 409, "renamed onto another folder's name");
    let names: Vec<String> = listed(&e).await.iter().map(|f| f["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["people and access", "Runbooks", "Заметки"]);
    for bad in [json!({"name": ""}), json!({"name": "x".repeat(81)}), json!({"name": 5}), json!({})] {
        let (status, refused) = request(&e, "PATCH", &format!("/api/folders/{tid}"), bad).await;
        assert_eq!(status, 422, "{refused}");
        assert_eq!(refused["error"], "A folder's name is 1 to 80 characters.");
    }
    let (status, gone) = request(&e, "DELETE", &format!("/api/folders/{tid}"), Value::Null).await;
    assert_eq!((status, gone["notes"].as_i64()), (200, Some(0)));
    let (status, _) = request(&e, "DELETE", &format!("/api/folders/{tid}"), Value::Null).await;
    assert_eq!(status, 404);
    // A folder is for Personal, the one project here.
    let (status, refused) = request(&e, "POST", "/api/folders", json!({"projectId": uuid::Uuid::new_v4().to_string(), "name": "Lab"})).await;
    assert_eq!((status, refused["error"].as_str()), (404, Some("No such project.")));
    let (status, refused) = request(&e, "POST", "/api/folders", json!({"name": "Lab"})).await;
    assert_eq!((status, refused["error"].as_str()), (422, Some("Say which project the folder is for.")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notes_saved_merged_ticked() {
    let (e, pid) = named().await;
    let me = e.settings.lock().unwrap().person_id.to_string();
    let f = folder(&e, &pid, "Release").await;
    let n = note(&e, f["id"].as_str().unwrap(), "Checklist").await;
    let id = n["id"].as_str().unwrap().to_string();
    assert_eq!((n["version"].as_i64(), n["title"].as_str(), &n["blocks"]), (Some(1), Some("Checklist"), &json!([])));
    assert_eq!((n["canDelete"].as_bool(), n["canWrite"].as_bool()), (Some(true), Some(true)));
    assert_eq!(n["folder"], "Release");
    assert_eq!(n["projectId"], pid.as_str());
    let (status, v2) = save(&e, &id, 1, "Checklist", json!([todo("a", "Freeze merges", false), todo("b", "Deploy", false), p("c", "If it goes wrong:")])).await;
    assert_eq!((status, v2["version"].as_i64()), (200, Some(2)), "{v2}");
    // The same save again changes nothing and keeps the version.
    let (_, same) = save(&e, &id, 2, "Checklist", v2["blocks"].clone()).await;
    assert_eq!(same["version"], 2);
    // A tick: who and when from the engine.
    let (status, ticked) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "a", "done": true})).await;
    assert_eq!(status, 200, "{ticked}");
    let item = &ticked["blocks"][0];
    assert_eq!((ticked["version"].as_i64(), item["done"].as_bool()), (Some(3), Some(true)));
    assert_eq!(item["by"], me.as_str());
    assert!(item["at"].is_i64());
    assert_eq!(ticked["people"][&me]["initials"], "DG");
    // An item that is not there, or not a checklist item: refused, but not as
    // a note that is gone.
    for block in ["zz", "c"] {
        let (status, refused) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": block, "done": true})).await;
        assert_eq!((status, refused["error"].as_str()), (422, Some("That item is not in the checklist any more.")), "ticked {block}");
    }
    // Another tab saves from version 2: its text change stays, the tick
    // stays, and the page cannot take the tick off by saving.
    let (_, merged) = save(&e, &id, 2, "Checklist", json!([todo("a", "Freeze merges to main", false), todo("b", "Deploy", true), p("c", "If it goes wrong:")])).await;
    assert_eq!(merged["version"], 4, "{merged}");
    let (a, b) = (&merged["blocks"][0], &merged["blocks"][1]);
    assert_eq!((a["text"].as_str(), a["done"].as_bool(), a["by"].as_str()), (Some("Freeze merges to main"), Some(true), Some(me.as_str())));
    assert_eq!(b["done"], false, "ticks come only through tick");
    let listed_note = listed(&e).await[0]["notes"][0].clone();
    assert_eq!((listed_note["total"].as_i64(), listed_note["done"].as_i64(), listed_note["excerpt"].as_str()), (Some(2), Some(1), Some("If it goes wrong:")));
    // The same block changed two ways: a conflict, with the note as now.
    let (status, conflict) = save(&e, &id, 3, "Checklist", json!([todo("a", "Freeze everything", false), todo("b", "Deploy", false), p("c", "If it goes wrong:")])).await;
    assert_eq!((status, conflict["conflict"].as_bool()), (409, Some(true)), "{conflict}");
    assert_eq!(conflict["note"]["version"], 4);
    assert_eq!(conflict["error"], "The note changed elsewhere meanwhile.");
    // The page merges on its own, keeping its text where both changed, and
    // saves that from the version the conflict named.
    let (_, resolved) = save(&e, &id, 4, "Checklist", json!([todo("a", "Freeze everything", false), todo("b", "Deploy", false), p("c", "If it goes wrong:")])).await;
    assert_eq!(resolved["version"], 5);
    assert_eq!(resolved["blocks"][0]["text"], "Freeze everything");
    assert_eq!(resolved["blocks"][0]["done"], true, "the tick stays the engine's");
    // A new item may come ticked: by whoever saved it.
    let mut more = resolved["blocks"].as_array().unwrap().clone();
    more.push(todo("d", "Tell the client", true));
    let (_, more) = save(&e, &id, 5, "Checklist", Value::Array(more)).await;
    assert_eq!(more["blocks"][3]["by"], me.as_str());
    // A version from the future cannot be merged; one that never was is not
    // a version at all.
    let (status, _) = save(&e, &id, 99, "x", json!([])).await;
    assert_eq!(status, 409);
    for base in [Value::Null, json!(0), json!(1i64 << 31), json!(true), json!("4"), json!(4.0)] {
        let mut body = json!({"title": "x"});
        if !base.is_null() {
            body["baseVersion"] = base.clone();
        }
        let (status, refused) = request(&e, "PUT", &format!("/api/notes/{id}"), body).await;
        assert_eq!((status, refused["error"].as_str()), (422, Some("Say which version the save was made from.")), "{base}");
    }
    // Untick, and tick nothing twice: no new version for nothing.
    let (_, off) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "a", "done": false})).await;
    assert_eq!((off["blocks"][0]["done"].as_bool(), off["blocks"][0]["by"].is_null(), off["blocks"][0]["at"].is_null()), (Some(false), true, true));
    let (_, again) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "a", "done": false})).await;
    assert_eq!(again["version"], off["version"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_versions_are_dropped() {
    let (e, pid) = named().await;
    let f = folder(&e, &pid, "F").await;
    let n = note(&e, f["id"].as_str().unwrap(), "").await;
    let id = n["id"].as_str().unwrap();
    let mut version = 1;
    for i in 0..notes::KEEP_VERSIONS + 10 {
        let (_, saved) = save(&e, id, version, "", json!([p("a", &i.to_string())])).await;
        version = saved["version"].as_i64().unwrap();
    }
    assert_eq!(count(&e, "note_versions").await, notes::KEEP_VERSIONS);
    // Saved from a version long gone: asked whose to keep.
    let (status, _) = save(&e, id, 2, "", json!([p("a", "late")])).await;
    assert_eq!(status, 409);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moving_and_deleting() {
    let (e, pid) = named().await;
    let a = folder(&e, &pid, "A").await;
    let b = folder(&e, &pid, "B").await;
    let n = note(&e, a["id"].as_str().unwrap(), "N").await;
    let nid = n["id"].as_str().unwrap().to_string();
    let (status, moved) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"folderId": b["id"]})).await;
    assert_eq!(status, 200, "{moved}");
    assert_eq!((moved["folderId"].as_str(), moved["folder"].as_str()), (b["id"].as_str(), Some("B")));
    // Not into a folder that is not there, nor into a project that is not.
    let (status, refused) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"folderId": uuid::Uuid::new_v4().to_string()})).await;
    assert_eq!((status, refused["error"].as_str()), (404, Some("No such folder.")));
    let (status, refused) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"projectId": uuid::Uuid::new_v4().to_string()})).await;
    assert_eq!((status, refused["error"].as_str()), (404, Some("No such project.")));
    note(&e, b["id"].as_str().unwrap(), "Second").await;
    // The lists: the newest first, and who wrote and edited each.
    let folders = listed(&e).await;
    let in_b = folders.iter().find(|f| f["name"] == "B").unwrap()["notes"].as_array().unwrap().clone();
    let titles: Vec<&str> = in_b.iter().map(|n| n["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Second", "N"]);
    assert_eq!(in_b[0]["createdBy"]["name"], "Denis Gerasimenko");
    assert_eq!(in_b[0]["editedBy"]["initials"], "DG");
    assert_eq!(in_b[1]["version"], 1, "the version, to tell copies apart");
    let (status, gone) = request(&e, "DELETE", &format!("/api/notes/{nid}"), Value::Null).await;
    assert_eq!((status, gone["title"].as_str(), gone["folder"].as_str()), (200, Some("N"), Some("B")));
    let (status, folder_gone) = request(&e, "DELETE", &format!("/api/folders/{}", b["id"].as_str().unwrap()), Value::Null).await;
    assert_eq!((status, folder_gone["notes"].as_i64()), (200, Some(1)));
    assert_eq!(count(&e, "notes").await, 0);
    assert_eq!(count(&e, "note_versions").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_works_with_notes() {
    let e = engine().await;
    let (_, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert_eq!(state["local"], true);
    let project = &state["projects"][0];
    assert_eq!(project["folders"], json!([]));
    let pid = project["id"].as_str().unwrap();
    let (status, f) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": "Runbooks"})).await;
    assert_eq!(status, 201, "{f}");
    let (status, _) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": "runbooks"})).await;
    assert_eq!(status, 409);
    let (status, n) = request(&e, "POST", "/api/notes", json!({"folderId": f["id"]})).await;
    assert_eq!((status, n["title"].as_str()), (201, Some("")), "{n}");
    let id = n["id"].as_str().unwrap().to_string();
    let (status, saved) = save(&e, &id, 1, "Deploy web-01", json!([{"id": "a", "type": "code", "text": "git pull"}, todo("b", "Check it", false)])).await;
    assert_eq!((status, saved["version"].as_i64()), (200, Some(2)), "{saved}");
    let (status, ticked) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "b", "done": true})).await;
    assert_eq!((status, ticked["blocks"][1]["done"].as_bool()), (200, Some(true)));
    let (status, saved) = save(&e, &id, 2, "Deploy web-01", json!([{"id": "a", "type": "code", "text": "git pull --rebase"}, todo("b", "Check it", false)])).await;
    assert_eq!((status, saved["version"].as_i64()), (200, Some(4)), "{saved}");
    let (status, conflict) = save(&e, &id, 2, "Deploy web-01", json!([{"id": "a", "type": "code", "text": "git fetch"}, todo("b", "Check it", false)])).await;
    assert_eq!((status, conflict["conflict"].as_bool()), (409, Some(true)));
    assert_eq!(conflict["note"]["blocks"][0]["text"], "git pull --rebase");
    let (status, _) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "zz", "done": true})).await;
    assert_eq!(status, 422);
    let (status, _) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "b"})).await;
    assert_eq!(status, 422);
    let folders = listed(&e).await;
    assert_eq!(folders[0]["name"], "Runbooks");
    let notes_listed: Vec<(String, i64, i64, String)> = folders[0]["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["title"].as_str().unwrap().into(), n["total"].as_i64().unwrap(), n["done"].as_i64().unwrap(), n["excerpt"].as_str().unwrap().into()))
        .collect();
    assert_eq!(notes_listed, [("Deploy web-01".to_string(), 1, 1, "git pull --rebase".to_string())]);
    // Too big to read at all.
    let huge = json!({"baseVersion": 4, "title": "", "blocks": [p("a", &"x".repeat(1_100_000))]}).to_string();
    let r = api::handle(&e, "PUT", &format!("/api/notes/{id}"), huge.as_bytes()).await;
    assert_eq!(r.status, 413);
    // Half a character, as JSON from a page can carry: refused in the core's
    // words, with nothing saved.
    let broken = r#"{"baseVersion": 4, "title": "", "blocks": [{"id": "a", "type": "p", "text": "broken \ud800"}]}"#;
    let r = api::handle(&e, "PUT", &format!("/api/notes/{id}"), broken.as_bytes()).await;
    assert_eq!(r.status, 422);
    assert!(String::from_utf8_lossy(&r.body).contains("broken character"), "{}", String::from_utf8_lossy(&r.body));
    let r = api::handle(&e, "PUT", &format!("/api/notes/{id}"), b"{not json").await;
    assert_eq!(r.status, 422);
    let (status, kept) = request(&e, "GET", &format!("/api/notes/{id}"), Value::Null).await;
    assert_eq!((status, kept["version"].as_i64()), (200, Some(4)));
    // Deleted: the note, then the folder.
    let (status, gone) = request(&e, "DELETE", &format!("/api/notes/{id}"), Value::Null).await;
    assert_eq!((status, gone["title"].as_str()), (200, Some("Deploy web-01")));
    let (status, _) = request(&e, "GET", &format!("/api/notes/{id}"), Value::Null).await;
    assert_eq!(status, 404);
    for (method, path) in [("PUT", format!("/api/notes/{id}")), ("DELETE", format!("/api/notes/{id}")), ("POST", format!("/api/notes/{id}/tick"))] {
        let (status, refused) = request(&e, method, &path, json!({"baseVersion": 4, "blockId": "b", "done": true})).await;
        assert_eq!((status, refused["error"].as_str()), (404, Some("No such note.")), "{method} {path}");
    }
    let (status, empty) = request(&e, "DELETE", &format!("/api/folders/{}", f["id"].as_str().unwrap()), Value::Null).await;
    assert_eq!((status, empty["notes"].as_i64()), (200, Some(0)));
    let (status, _) = request(&e, "POST", "/api/notes", json!({"folderId": f["id"]})).await;
    assert_eq!(status, 404, "a note for a folder that went");
    let (status, _) = request(&e, "GET", "/api/notes/not-an-id", Value::Null).await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_moves_a_note_within_personal() {
    let e = engine().await;
    let pid = e.settings.lock().unwrap().project_id.to_string();
    let f = folder(&e, &pid, "Runbooks").await;
    let n = note(&e, f["id"].as_str().unwrap(), "Deploy").await;
    let nid = n["id"].as_str().unwrap();
    for body in [json!({}), json!({"folderId": f["id"], "projectId": pid})] {
        let (status, refused) = request(&e, "PATCH", &format!("/api/notes/{nid}"), body.clone()).await;
        assert_eq!((status, refused["error"].as_str()), (422, Some("Say where the note goes: a folder, or a project.")), "{body}");
    }
    // To Personal itself: it is there already, in its folder.
    let (status, stays) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"projectId": pid})).await;
    assert_eq!((status, stays["projectId"].as_str(), stays["folder"].as_str(), stays["title"].as_str()), (200, Some(pid.as_str()), Some("Runbooks"), Some("Deploy")));
    let (status, _) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"projectId": "not an id"})).await;
    assert_eq!(status, 422);
    let (status, stays) = request(&e, "PATCH", &format!("/api/notes/{nid}"), json!({"folderId": f["id"]})).await;
    assert_eq!((status, stays["projectId"].as_str()), (200, Some(pid.as_str())));
}

/// An engine as the app starts one, without the work it does alongside:
/// dropped, it lets go of its file, as when the app quits.
async fn started(dir: &std::path::Path) -> Arc<Engine> {
    Engine::new(dir).expect("engine")
}

/// The app quits: its engine goes, and the store's thread with it.
async fn quit(e: Arc<Engine>) {
    assert!(e.terminals.store.flush(Duration::from_secs(5)).await);
    drop(e);
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notes_stay_after_the_app_and_the_sweep() {
    let dir = common::data_dir();
    let e = started(&dir).await;
    request(&e, "PATCH", "/api/me", json!({"name": "Denis Gerasimenko"})).await;
    let pid = e.settings.lock().unwrap().project_id.to_string();
    let f = folder(&e, &pid, "Home").await;
    let n = note(&e, f["id"].as_str().unwrap(), "Kept").await;
    let id = n["id"].as_str().unwrap().to_string();
    save(&e, &id, 1, "Kept", json!([todo("a", "Stays", true), p("b", "Across runs of the app")])).await;
    // The hourly sweep takes old blocks of terminals, not notes.
    e.terminals.store.sweep();
    quit(e).await;
    let again = started(&dir).await;
    let state = again.state_json().await;
    let folders = state["projects"][0]["folders"].as_array().unwrap();
    assert_eq!((folders[0]["name"].as_str(), folders[0]["notes"][0]["title"].as_str()), (Some("Home"), Some("Kept")));
    assert_eq!(folders[0]["notes"][0]["total"], 1);
    let (status, read) = request(&again, "GET", &format!("/api/notes/{id}"), Value::Null).await;
    assert_eq!((status, read["blocks"][1]["text"].as_str(), read["version"].as_i64()), (200, Some("Across runs of the app"), Some(2)));
    assert_eq!(read["blocks"][0]["done"], true);
    assert_eq!(read["createdBy"]["name"], "Denis Gerasimenko");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_made_anew_find_the_notes() {
    let dir = common::data_dir();
    let e = started(&dir).await;
    request(&e, "PATCH", "/api/me", json!({"name": "Denis Gerasimenko"})).await;
    let (pid, me) = {
        let s = e.settings.lock().unwrap();
        (s.project_id.to_string(), s.person_id.to_string())
    };
    let f = folder(&e, &pid, "Runbooks").await;
    let n = note(&e, f["id"].as_str().unwrap(), "Deploy").await;
    let id = n["id"].as_str().unwrap().to_string();
    save(&e, &id, 1, "Deploy", json!([todo("a", "Check it", true)])).await;
    quit(e).await;
    // The settings file is lost, or damaged: new settings, the same ids.
    for broken in [None, Some(b"\xff not even text".to_vec())] {
        match broken {
            None => std::fs::remove_file(dir.join("settings.json")).unwrap(),
            Some(bytes) => std::fs::write(dir.join("settings.json"), bytes).unwrap(),
        }
        let again = started(&dir).await;
        {
            let s = again.settings.lock().unwrap();
            assert_eq!((s.project_id.to_string(), s.person_id.to_string()), (pid.clone(), me.clone()));
        }
        let state = again.state_json().await;
        assert_eq!(state["projects"][0]["id"], pid.as_str());
        assert_eq!(state["me"]["id"], me.as_str(), "drafts in the page are kept under it");
        assert_eq!(state["projects"][0]["folders"][0]["notes"][0]["title"], "Deploy");
        let (status, read) = request(&again, "GET", &format!("/api/notes/{id}"), Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(read["people"][&me]["id"], me.as_str(), "who ticked is the person still");
        quit(again).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_of_0_1_takes_notes() {
    let dir = common::data_dir();
    std::fs::create_dir_all(&dir).unwrap();
    {
        // As 0.1.2 left it: version 1, a terminal with a block.
        let c = rusqlite::Connection::open(dir.join("tterm.db")).unwrap();
        c.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL;
             CREATE TABLE terminals (id TEXT PRIMARY KEY, name TEXT NOT NULL, opened_at INTEGER NOT NULL, closed_at INTEGER,
                                     end_reason TEXT, shell TEXT, home TEXT, last_seq INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE blocks (id INTEGER PRIMARY KEY, terminal_id TEXT NOT NULL REFERENCES terminals (id) ON DELETE CASCADE,
                                  seq_start INTEGER NOT NULL, seq_end INTEGER, command TEXT, started_at INTEGER NOT NULL,
                                  finished_at INTEGER, exit_code INTEGER, cwd TEXT, branch TEXT, output BLOB,
                                  output_cut INTEGER NOT NULL DEFAULT 0, cols INTEGER, expires_at INTEGER NOT NULL);
             CREATE INDEX blocks_terminal ON blocks (terminal_id, seq_start);
             CREATE INDEX blocks_expiry ON blocks (expires_at);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        c.execute("INSERT INTO terminals (id, name, opened_at, closed_at, end_reason) VALUES ('00000000-0000-4000-8000-000000000001', 'old', 1, 2, 'Closed.')", []).unwrap();
    }
    let e = started(&dir).await;
    let version: i64 = e.terminals.store.run(|c| c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()).await.unwrap();
    assert_eq!(version, 2);
    let old = e.ended_json(&uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()).await.unwrap();
    assert_eq!((old["name"].as_str(), old["reason"].as_str()), (Some("old"), Some("Closed.")), "the terminals of 0.1 stay");
    let pid = e.settings.lock().unwrap().project_id.to_string();
    let f = folder(&e, &pid, "New").await;
    note(&e, f["id"].as_str().unwrap(), "First note").await;
    assert_eq!(listed(&e).await[0]["notes"][0]["title"], "First note");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_notes_are_taken_that_would_be_lost() {
    let dir = common::data_dir();
    std::fs::create_dir_all(dir.join("tterm.db")).unwrap();
    let e = started(&dir).await;
    assert!(e.terminals.store.path.is_none(), "the store lives in memory");
    assert!(e.terminals.store.trouble.is_some());
    let pid = e.settings.lock().unwrap().project_id.to_string();
    let (status, refused) = request(&e, "POST", "/api/folders", json!({"projectId": pid, "name": "Lost"})).await;
    assert_eq!(status, 503);
    assert!(refused["error"].as_str().unwrap().starts_with("Notes cannot be kept now"), "{refused}");
    let (status, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert_eq!((status, &state["projects"][0]["folders"]), (200, &json!([])), "the terminals go on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tick_is_a_yes_or_no_as_the_core_takes_it() {
    let (e, pid) = named().await;
    let f = folder(&e, &pid, "F").await;
    let n = note(&e, f["id"].as_str().unwrap(), "T").await;
    let id = n["id"].as_str().unwrap().to_string();
    save(&e, &id, 1, "T", json!([todo("a", "x", false)])).await;
    for (done, want) in [(json!("true"), true), (json!(0), false), (json!("Yes"), true), (json!("off"), false), (json!(1.0), true)] {
        let (status, ticked) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "a", "done": done})).await;
        assert_eq!((status, ticked["blocks"][0]["done"].as_bool()), (200, Some(want)), "{done}");
    }
    for done in [json!("maybe"), json!(2), json!(null), json!(1.5)] {
        let (status, _) = request(&e, "POST", &format!("/api/notes/{id}/tick"), json!({"blockId": "a", "done": done})).await;
        assert_eq!(status, 422, "{done}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notes_that_cannot_be_read_keep_neither_the_page_nor_the_terminals() {
    let (e, pid) = named().await;
    let f = folder(&e, &pid, "Runbooks").await;
    let n = note(&e, f["id"].as_str().unwrap(), "Deploy").await;
    let id = n["id"].as_str().unwrap().to_string();
    // Notes the store cannot read, as from a damaged part of the file.
    e.terminals.store.run(|c| c.execute_batch("ALTER TABLE notes RENAME TO notes_gone;").unwrap()).await.unwrap();
    let (status, state) = request(&e, "GET", "/api/state", Value::Null).await;
    assert_eq!((status, &state["projects"][0]["folders"]), (200, &json!([])), "the page starts, the terminals with it");
    for (method, path, body) in [
        ("POST", "/api/folders".to_string(), json!({"projectId": pid, "name": "More"})),
        ("GET", format!("/api/notes/{id}"), Value::Null),
        ("PUT", format!("/api/notes/{id}"), json!({"baseVersion": 1, "title": "x", "blocks": []})),
    ] {
        let (status, refused) = request(&e, method, &path, body).await;
        assert_eq!(status, 503, "{method} {path}");
        assert!(refused["error"].as_str().unwrap().starts_with("The notes on this computer could not be read"), "{refused}");
    }
    // Readable again: all as before.
    e.terminals.store.run(|c| c.execute_batch("ALTER TABLE notes_gone RENAME TO notes;").unwrap()).await.unwrap();
    assert_eq!(listed(&e).await[0]["notes"][0]["title"], "Deploy");
    let (status, _) = request(&e, "GET", &format!("/api/notes/{id}"), Value::Null).await;
    assert_eq!(status, 200);
}
