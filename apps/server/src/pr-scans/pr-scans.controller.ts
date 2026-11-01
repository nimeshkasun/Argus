import { Body, Controller, Get, HttpCode, Param, ParseUUIDPipe, Post, Query, Req, Res } from '@nestjs/common';
import { listPrScansQuerySchema, prScanRequestSchema } from '@argus/shared';
import { type Request, type Response } from 'express';
import { type z } from 'zod';
import { CurrentUser, RequirePermissions } from '../auth/decorators';
import { type RequestUser, requestContext } from '../common/request';
import { ZodPipe } from '../common/zod.pipe';
import { PrScansService } from './pr-scans.service';

/**
 * Pull request scans for CI pipelines (GitHub Actions, Bitbucket Pipelines, ...), authenticated with an Argus API
 * token in "Authorization: Bearer argus_pat_…". The pipeline requests a scan, then polls it until it has finished.
 */
@Controller('ci/pull-requests')
export class PrScansController {
  constructor(private readonly scans: PrScansService) {}

  /** 202 with the queued scan, or 200 with the scan already running for this pull request and commit. */
  @Post()
  @HttpCode(202)
  @RequirePermissions('scans:run')
  async request(@Body(new ZodPipe(prScanRequestSchema)) body: z.infer<typeof prScanRequestSchema>, @CurrentUser() me: RequestUser, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const { scan, created } = await this.scans.request(body, me.user, requestContext(req));
    if (!created) res.status(200);
    return scan;
  }

  @Get()
  @RequirePermissions('repos:read')
  list(@Query(new ZodPipe(listPrScansQuerySchema)) q: z.infer<typeof listPrScansQuerySchema>, @CurrentUser() me: RequestUser) {
    return this.scans.list(q.repoId, q, me.user);
  }

  @Get(':id')
  @RequirePermissions('repos:read')
  get(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() me: RequestUser) {
    return this.scans.get(id, me.user);
  }
}
