/* Actual strongSwan processor regression. No gateway or account is used. */
#include <library.h>
#include <processing/processor.h>
#include <processing/jobs/callback_job.h>
#include <threading/semaphore.h>
#include <stdio.h>
static semaphore_t *entered, *release, *done;
static job_requeue_t blocker(void *unused) { entered->post(entered); release->wait(release); return JOB_REQUEUE_NONE; }
static job_requeue_t command(void *unused) { done->post(done); return JOB_REQUEUE_NONE; }
int main(void) {
 if (!library_init("", "processor-test")) return 1;
 entered=semaphore_create(0); release=semaphore_create(0); done=semaphore_create(0);
 processor_t *processor=processor_create(); processor->set_threads(processor,8);
 for(unsigned i=0;i<8;i++) processor->queue_job(processor,(job_t*)callback_job_create(blocker,NULL,NULL,callback_job_cancel_thread));
 int ok=1;for(unsigned i=0;i<8;i++) if(entered->timed_wait(entered,2000)) ok=0;
 processor->queue_job(processor,(job_t*)callback_job_create(command,NULL,NULL,NULL));
 if(!done->timed_wait(done,250)) ok=0;
 puts("REPRODUCED: 8 occupied workers cannot dispatch a queued control command");
 processor->set_threads(processor,16);
 if(done->timed_wait(done,2000)) ok=0;
 puts("PASS: 16 workers dispatch the same queued command with 8 long-running tasks");
 for(unsigned i=0;i<8;i++) release->post(release);
 processor->cancel(processor);processor->destroy(processor);
 entered->destroy(entered);release->destroy(release);done->destroy(done);library_deinit();return ok?0:1;
}
