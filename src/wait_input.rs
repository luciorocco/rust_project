use std::io::stdin;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

pub(crate) fn wait_pause(cv: Arc<(Mutex<bool>, Condvar)>, cv6: Arc<(Mutex<bool>, Condvar)>, atm: &Arc<AtomicBool>, ext: &Arc<AtomicBool>, sender: Sender<String>){
    let mut s = String::new();
    let (lock,cvar ) = &*cv;

    'outer: loop{
        println!("Press P for pause or E for exit and save on file");
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().to_ascii_lowercase().as_str() {
            "p" => {
                s.clear();
                atm.store(true, Ordering::Relaxed);
                let mut guard = cvar.wait_while(lock.lock().unwrap(),|pending|{
                    *pending
                }).unwrap();
                let (lock1,cvar1 ) = &*cv6;
                let mut started = lock1.lock().unwrap();
                *started = true;
                cvar1.notify_all();
                'inner : loop{
                    println!("Press R for resume or E to exit..");
                    stdin().read_line(&mut s).ok().expect("Failed to read line");
                    match s.trim().to_ascii_lowercase().as_str() {
                        "r" => {
                            s.clear();
                            atm.store(false, Ordering::Relaxed);
                            *guard = true;
                            cvar.notify_all();
                            *started = false;
                            cvar1.notify_all();
                            break 'inner
                        },
                        "e" => {
                            ext.store(true, Ordering::Relaxed);
                            *guard = true;
                            cvar.notify_all();
                            *started = false;
                            cvar1.notify_all();
                            break 'outer
                        }
                        _ => {
                            s.clear();
                            println!("Command Not Found...");
                            continue
                        }
                    }

                }
            },
            "e" => {
                ext.store(true, Ordering::Relaxed);
                atm.store(true, Ordering::Relaxed);
                let mut guard = cvar.wait_while(lock.lock().unwrap(),|pending|{
                    *pending
                }).unwrap();
                *guard = true;
                cvar.notify_all();
                break 'outer
            }
            _ => {
                s.clear();
                println!("Command Not Found...");
                continue
            }
        }
    }
    sender.send("e".to_string());
}