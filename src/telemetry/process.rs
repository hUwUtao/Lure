/// This service is to monitor tokio runtime (instead of the whole rust process).
/// The reason is...to monitor! `tokio_unstable` is on by default and I have no reason to refuse that.
/// Disable `tokio_unstable` feature, and maybe override flags if you are too -phobic and ith it's fine.
use std::time::Duration;

use opentelemetry::metrics::{Counter, Gauge};
use tokio_metrics::RuntimeMonitor;

use crate::{telemetry::get_meter, utils::spawn_named};

#[cfg(feature = "tokio_unstable")]
struct UnstableMetrics {
    total_noop_count: Counter<u64>,
    max_noop_count: Counter<u64>,
    min_noop_count: Counter<u64>,
    total_steal_count: Counter<u64>,
    max_steal_count: Counter<u64>,
    min_steal_count: Counter<u64>,
    total_steal_operations: Counter<u64>,
    max_steal_operations: Counter<u64>,
    min_steal_operations: Counter<u64>,
    num_remote_schedules: Counter<u64>,
    total_local_schedule_count: Counter<u64>,
    max_local_schedule_count: Counter<u64>,
    min_local_schedule_count: Counter<u64>,
    total_overflow_count: Counter<u64>,
    max_overflow_count: Counter<u64>,
    min_overflow_count: Counter<u64>,
    total_polls_count: Counter<u64>,
    max_polls_count: Counter<u64>,
    min_polls_count: Counter<u64>,
    total_local_queue_depth: Gauge<u64>,
    max_local_queue_depth: Gauge<u64>,
    min_local_queue_depth: Gauge<u64>,
    blocking_queue_depth: Gauge<u64>,
    live_tasks_count: Gauge<u64>,
    blocking_threads_count: Gauge<u64>,
    idle_blocking_threads_count: Gauge<u64>,
    budget_forced_yield_count: Counter<u64>,
    io_driver_ready_count: Counter<u64>,
    busy_ratio: Gauge<f64>,
    mean_polls_per_park: Gauge<f64>,
}

pub struct ProcessMetricsService {
    // Stable Runtime Metrics
    workers_count: Gauge<u64>,
    total_park_count: Gauge<u64>,
    max_park_count: Gauge<u64>,
    min_park_count: Gauge<u64>,
    total_busy_duration: Counter<u64>,
    max_busy_duration: Counter<u64>,
    min_busy_duration: Counter<u64>,
    global_queue_depth: Gauge<u64>,

    // Unstable Runtime Metrics

    // Task Metrics
    // instrumented_count: Counter<u64>,
    // dropped_count: Counter<u64>,
    // first_poll_count: Counter<u64>,
    // total_first_poll_delay: Histogram<f64>,
    // total_idled_count: Counter<u64>,
    // total_idle_duration: Histogram<f64>,
    // total_scheduled_count: Counter<u64>,
    // total_scheduled_duration: Histogram<f64>,
    // total_poll_count: Counter<u64>,
    // total_poll_duration: Histogram<f64>,
    // total_fast_poll_count: Counter<u64>,
    // total_fast_poll_duration: Histogram<f64>,
    // total_slow_poll_count: Counter<u64>,
    // total_slow_poll_duration: Histogram<f64>,
    // total_short_delay_count: Counter<u64>,
    // total_short_delay_duration: Histogram<f64>,
    // total_long_delay_count: Counter<u64>,
    // total_long_delay_duration: Histogram<f64>,
    #[cfg(feature = "tokio_unstable")]
    unstable: UnstableMetrics,

    // Internal monitors
    runtime_monitor: RuntimeMonitor,
    // task_monitor: TaskMonitor,
}

impl ProcessMetricsService {
    pub fn new() -> Self {
        let meter = get_meter();
        let handle = tokio::runtime::Handle::current();

        #[cfg(feature = "tokio_unstable")]
        let unstable_metrics = UnstableMetrics {
            // Initialize unstable runtime metrics
            total_noop_count: meter.u64_counter("tokio_total_noop_count").build(),
            max_noop_count: meter.u64_counter("tokio_max_noop_count").build(),
            min_noop_count: meter.u64_counter("tokio_min_noop_count").build(),
            total_steal_count: meter.u64_counter("tokio_total_steal_count").build(),
            max_steal_count: meter.u64_counter("tokio_max_steal_count").build(),
            min_steal_count: meter.u64_counter("tokio_min_steal_count").build(),
            total_steal_operations: meter.u64_counter("tokio_total_steal_operations").build(),
            max_steal_operations: meter.u64_counter("tokio_max_steal_operations").build(),
            min_steal_operations: meter.u64_counter("tokio_min_steal_operations").build(),
            num_remote_schedules: meter.u64_counter("tokio_num_remote_schedules").build(),
            total_local_schedule_count: meter
                .u64_counter("tokio_total_local_schedule_count")
                .build(),
            max_local_schedule_count: meter.u64_counter("tokio_max_local_schedule_count").build(),
            min_local_schedule_count: meter.u64_counter("tokio_min_local_schedule_count").build(),
            total_overflow_count: meter.u64_counter("tokio_total_overflow_count").build(),
            max_overflow_count: meter.u64_counter("tokio_max_overflow_count").build(),
            min_overflow_count: meter.u64_counter("tokio_min_overflow_count").build(),
            total_polls_count: meter.u64_counter("tokio_total_polls_count").build(),
            max_polls_count: meter.u64_counter("tokio_max_polls_count").build(),
            min_polls_count: meter.u64_counter("tokio_min_polls_count").build(),
            total_local_queue_depth: meter.u64_gauge("tokio_total_local_queue_depth").build(),
            max_local_queue_depth: meter.u64_gauge("tokio_max_local_queue_depth").build(),
            min_local_queue_depth: meter.u64_gauge("tokio_min_local_queue_depth").build(),
            blocking_queue_depth: meter.u64_gauge("tokio_blocking_queue_depth").build(),
            live_tasks_count: meter.u64_gauge("tokio_live_tasks_count").build(),
            blocking_threads_count: meter.u64_gauge("tokio_blocking_threads_count").build(),
            idle_blocking_threads_count: meter
                .u64_gauge("tokio_idle_blocking_threads_count")
                .build(),
            budget_forced_yield_count: meter.u64_counter("tokio_budget_forced_yield_count").build(),
            io_driver_ready_count: meter.u64_counter("tokio_io_driver_ready_count").build(),
            busy_ratio: meter.f64_gauge("tokio_busy_ratio").build(),
            mean_polls_per_park: meter.f64_gauge("tokio_mean_polls_per_park").build(),
        };

        Self {
            // Initialize stable runtime metrics
            workers_count: meter.u64_gauge("tokio_workers_count").build(),
            total_park_count: meter.u64_gauge("tokio_total_park_count").build(),
            max_park_count: meter.u64_gauge("tokio_max_park_count").build(),
            min_park_count: meter.u64_gauge("tokio_min_park_count").build(),
            total_busy_duration: meter.u64_counter("tokio_total_busy_duration").build(),
            max_busy_duration: meter.u64_counter("tokio_max_busy_duration").build(),
            min_busy_duration: meter.u64_counter("tokio_min_busy_duration").build(),
            global_queue_depth: meter.u64_gauge("tokio_global_queue_depth").build(),

            #[cfg(feature = "tokio_unstable")]
            unstable: unstable_metrics,
            // Initialize task metrics
            // instrumented_count: meter.u64_counter("tokio_instrumented_count").build(),
            // dropped_count: meter.u64_counter("tokio_dropped_count").build(),
            // first_poll_count: meter.u64_counter("tokio_first_poll_count").build(),
            // total_first_poll_delay: meter.f64_histogram("tokio_total_first_poll_delay").build(),
            // total_idled_count: meter.u64_counter("tokio_total_idled_count").build(),
            // total_idle_duration: meter.f64_histogram("tokio_total_idle_duration").build(),
            // total_scheduled_count: meter.u64_counter("tokio_total_scheduled_count").build(),
            // total_scheduled_duration: meter
            //     .f64_histogram("tokio_total_scheduled_duration")
            //     .build(),
            // total_poll_count: meter.u64_counter("tokio_total_poll_count").build(),
            // total_poll_duration: meter.f64_histogram("tokio_total_poll_duration").build(),
            // total_fast_poll_count: meter.u64_counter("tokio_total_fast_poll_count").build(),
            // total_fast_poll_duration: meter
            //     .f64_histogram("tokio_total_fast_poll_duration")
            //     .build(),
            // total_slow_poll_count: meter.u64_counter("tokio_total_slow_poll_count").build(),
            // total_slow_poll_duration: meter
            //     .f64_histogram("tokio_total_slow_poll_duration")
            //     .build(),
            // total_short_delay_count: meter.u64_counter("tokio_total_short_delay_count").build(),
            // total_short_delay_duration: meter
            //     .f64_histogram("tokio_total_short_delay_duration")
            //     .build(),
            // total_long_delay_count: meter.u64_counter("tokio_total_long_delay_count").build(),
            // total_long_delay_duration: meter
            //     .f64_histogram("tokio_total_long_delay_duration")
            //     .build(),

            // Initialize monitors
            runtime_monitor: RuntimeMonitor::new(&handle),
            // task_monitor: TaskMonitor::new(),
        }
    }

    fn update_runtime_metrics(&self, metrics: &tokio_metrics::RuntimeMetrics) {
        // Common labels for all metrics
        let common_labels = &[];

        // Update stable runtime metrics with labels
        self.workers_count
            .record(metrics.workers_count as u64, common_labels);
        self.total_park_count
            .record(metrics.total_park_count, common_labels);
        self.max_park_count
            .record(metrics.max_park_count, common_labels);
        self.min_park_count
            .record(metrics.min_park_count, common_labels);
        self.total_busy_duration.add(
            metrics.total_busy_duration.as_micros() as u64,
            common_labels,
        );
        self.max_busy_duration
            .add(metrics.max_busy_duration.as_micros() as u64, common_labels);
        self.min_busy_duration
            .add(metrics.min_busy_duration.as_micros() as u64, common_labels);
        self.global_queue_depth
            .record(metrics.global_queue_depth as u64, common_labels);

        // Update unstable runtime metrics with labels
        #[cfg(feature = "tokio_unstable")]
        {
            // Noops metrics
            self.unstable
                .total_noop_count
                .add(metrics.total_noop_count, common_labels);
            self.unstable
                .max_noop_count
                .add(metrics.max_noop_count, common_labels);
            self.unstable
                .min_noop_count
                .add(metrics.min_noop_count, common_labels);

            // Steal metrics
            self.unstable
                .total_steal_count
                .add(metrics.total_steal_count, common_labels);
            self.unstable
                .max_steal_count
                .add(metrics.max_steal_count, common_labels);
            self.unstable
                .min_steal_count
                .add(metrics.min_steal_count, common_labels);
            self.unstable
                .total_steal_operations
                .add(metrics.total_steal_operations, common_labels);
            self.unstable
                .max_steal_operations
                .add(metrics.max_steal_operations, common_labels);
            self.unstable
                .min_steal_operations
                .add(metrics.min_steal_operations, common_labels);

            // Schedule metrics
            self.unstable
                .num_remote_schedules
                .add(metrics.num_remote_schedules, common_labels);
            self.unstable
                .total_local_schedule_count
                .add(metrics.total_local_schedule_count, common_labels);
            self.unstable
                .max_local_schedule_count
                .add(metrics.max_local_schedule_count, common_labels);
            self.unstable
                .min_local_schedule_count
                .add(metrics.min_local_schedule_count, common_labels);

            // Overflow metrics
            self.unstable
                .total_overflow_count
                .add(metrics.total_overflow_count, common_labels);
            self.unstable
                .max_overflow_count
                .add(metrics.max_overflow_count, common_labels);
            self.unstable
                .min_overflow_count
                .add(metrics.min_overflow_count, common_labels);

            // Poll metrics
            self.unstable
                .total_polls_count
                .add(metrics.total_polls_count, common_labels);
            self.unstable
                .max_polls_count
                .add(metrics.max_polls_count, common_labels);
            self.unstable
                .min_polls_count
                .add(metrics.min_polls_count, common_labels);

            self.unstable
                .total_local_queue_depth
                .record(metrics.total_local_queue_depth as u64, common_labels);
            self.unstable
                .max_local_queue_depth
                .record(metrics.max_local_queue_depth as u64, common_labels);
            self.unstable
                .min_local_queue_depth
                .record(metrics.min_local_queue_depth as u64, common_labels);
            self.unstable
                .blocking_queue_depth
                .record(metrics.blocking_queue_depth as u64, common_labels);

            // Task and thread metrics
            self.unstable
                .live_tasks_count
                .record(metrics.live_tasks_count as u64, common_labels);
            self.unstable
                .blocking_threads_count
                .record(metrics.blocking_threads_count as u64, common_labels);
            self.unstable
                .idle_blocking_threads_count
                .record(metrics.idle_blocking_threads_count as u64, common_labels);

            // Performance metrics
            self.unstable
                .budget_forced_yield_count
                .add(metrics.budget_forced_yield_count, common_labels);
            self.unstable
                .io_driver_ready_count
                .add(metrics.io_driver_ready_count, common_labels);

            // Derived metrics
            self.unstable
                .busy_ratio
                .record(metrics.busy_ratio(), common_labels);
            self.unstable
                .mean_polls_per_park
                .record(metrics.mean_polls_per_park(), common_labels);
        }
    }

    // fn update_task_metrics(&self, metrics: &tokio_metrics::TaskMetrics) {
    //     let common_labels = &[];
    //
    //     // Base metrics
    //     self.instrumented_count
    //         .add(metrics.instrumented_count, common_labels);
    //     self.dropped_count.add(metrics.dropped_count, common_labels);
    //     self.first_poll_count
    //         .add(metrics.first_poll_count, common_labels);
    //
    //     // Delay metrics
    //     self.total_first_poll_delay
    //         .record(metrics.total_first_poll_delay.as_secs_f64(), common_labels);
    //
    //     // Idle metrics
    //     self.total_idled_count
    //         .add(metrics.total_idled_count, common_labels);
    //     self.total_idle_duration
    //         .record(metrics.total_idle_duration.as_secs_f64(), common_labels);
    //
    //     // Schedule metrics
    //     self.total_scheduled_count
    //         .add(metrics.total_scheduled_count, common_labels);
    //     self.total_scheduled_duration.record(
    //         metrics.total_scheduled_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //
    //     // Poll metrics
    //     self.total_poll_count
    //         .add(metrics.total_poll_count, common_labels);
    //     self.total_poll_duration
    //         .record(metrics.total_poll_duration.as_secs_f64(), common_labels);
    //
    //     // Fast/Slow poll metrics
    //     self.total_fast_poll_count
    //         .add(metrics.total_fast_poll_count, common_labels);
    //     self.total_fast_poll_duration.record(
    //         metrics.total_fast_poll_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //     self.total_slow_poll_count
    //         .add(metrics.total_slow_poll_count, common_labels);
    //     self.total_slow_poll_duration.record(
    //         metrics.total_slow_poll_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //
    //     // Delay count and duration metrics
    //     self.total_short_delay_count
    //         .add(metrics.total_short_delay_count, common_labels);
    //     self.total_short_delay_duration.record(
    //         metrics.total_short_delay_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //     self.total_long_delay_count
    //         .add(metrics.total_long_delay_count, common_labels);
    //     self.total_long_delay_duration.record(
    //         metrics.total_long_delay_duration.as_secs_f64(),
    //         common_labels,
    //     );
    // }

    pub fn start(&'static self) {
        // Spawn runtime metrics collection task
        spawn_named("Runtime metrics", async move {
            for metrics in self.runtime_monitor.intervals() {
                self.update_runtime_metrics(&metrics);
                // currently I have no idea how to change otel report rate
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        })
        .unwrap();

        // Spawn task metrics collection task
        // tokio::spawn(async move {
        //     for metrics in self.task_monitor.intervals() {
        //         self.update_task_metrics(&metrics);
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //     }
        // });
    }

    // pub fn instrument<T>(&self, task: T) -> impl std::future::Future<Output = T::Output>
    // where
    //     T: std::future::Future,
    // {
    //     self.task_monitor.instrument(task)
    // }
    //
    // pub fn instrument_batch<I, F, Fut>(&self, tasks: I) -> Vec<impl std::future::Future<Output = Fut::Output>>
    // where
    //     I: IntoIterator<Item = F>,
    //     F: FnOnce() -> Fut,
    //     Fut: std::future::Future,
    // {
    //     tasks.into_iter()
    //         .map(|task| self.instrument(task()))
    //         .collect()
    // }
}
