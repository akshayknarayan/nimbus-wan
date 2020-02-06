use failure::Error;
use slog::Drain;
use std::sync::Mutex;
use structopt::StructOpt;
use tsunami::{providers::aws::Setup, providers::Launcher, TsunamiBuilder};

#[derive(StructOpt)]
struct Opt {
    #[structopt(long)]
    region: Vec<String>,
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = Mutex::new(slog_term::FullFormat::new(decorator).build()).fuse();
    let log = slog::Logger::root(drain, slog::o!());

    let mut b = TsunamiBuilder::default();
    b.set_logger(log.clone());
    for reg in opt.region {
        register_node(&mut b, &reg)?;
    }

    let mut aws: tsunami::providers::aws::Launcher<_> = Default::default();
    aws.open_ports();

    b.spawn(&mut aws)?;
    let vms = aws.connect_all()?;

    for (name, mach) in vms {
        let node = cloud::Node {
            ssh: mach.ssh.as_ref().expect("ssh connection"),
            name: &name,
            ip: &mach.public_ip,
            user: "ubuntu",
        };

        cloud::aws_to_local(
            "cubic",
            std::path::Path::new(&format!("./{}", name)),
            &log,
            &node,
        )
        .unwrap_or_else(|_| {
            slog::debug!(
                &log,
                "pausing for manual instance inspection, press enter to continue"
            );

            use std::io::prelude::*;
            let stdin = std::io::stdin();
            let mut iterator = stdin.lock().lines();
            iterator.next().unwrap().unwrap();
        });
    }

    Ok(())
}

fn register_node(b: &mut TsunamiBuilder<Setup>, r: &str) -> Result<String, Error> {
    let m = Setup::default()
        .region_with_ubuntu_ami(r.clone().parse()?)
        .instance_type("t3.medium")
        .setup(|ssh, log| {
            cloud::install_basic_packages(ssh).map_err(|e| e.context("apt install failed"))?;
            slog::debug!(log, "finished apt install"; "node" => "m0");
            ssh.cmd("sudo sysctl -w net.ipv4.tcp_wmem=\"4096000 50331648 50331648\"")
                .map(|(_, _)| ())?;
            ssh.cmd("sudo sysctl -w net.ipv4.tcp_rmem=\"4096000 50331648 50331648\"")
                .map(|(_, _)| ())?;
            ssh.cmd("git clone --recursive https://github.com/akshayknarayan/cc-exp-tools ~/tools")
                .map(|(_, _)| ())?;
            ssh.cmd("sudo modprobe tcp_bbr").map(|(_, _)| ())?;
            ssh.cmd("sudo modprobe tcp_vegas").map(|(_, _)| ())?;
            ssh.cmd(
                "sudo sysctl -w net.ipv4.tcp_allowed_congestion_control=\"reno cubic bbr vegas\"",
            )
            .map(|(_, _)| ())?;

            slog::debug!(log, "compiling tools"; "node" => "m0");
            ssh.cmd("make -C tools").map(|(_, _)| ())?;

            slog::debug!(log, "load ccp_kernel"; "node" => "m0");
            ssh.cmd("cd ~/tools/ccp-kernel && sudo ./ccp_kernel_load ipc=0")
                .map(|(_, _)| ())?;
            Ok(())
        });

    let name = format!("aws_{}", r.replace("-", ""));
    b.add(&name, m)?;
    Ok(name)
}
